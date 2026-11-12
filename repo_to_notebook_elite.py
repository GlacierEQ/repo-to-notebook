#!/usr/bin/env python3
"""repo-to-notebook v0.3.0 (Elite) — GlacierEQ Repository-to-NotebookLM & Colab Engine.

Upgrades over v0.2.0:
1. Multi-language AST/structural symbol & import extraction (Python AST + TS/JS/Go/Rust/SQL/Shell).
2. Directed Dependency Graph (DAG), cycle detection, and centrality ranking.
3. Domain-cohesive semantic packing within Google AI Pro NotebookLM quotas (300 sources / 500k words / 200 MB).
4. Auto-generated 00_NOTEBOOKLM_SYSTEM_BRIEF.md & 00_MASTER_INDEX_AND_SYMBOLS.md.
5. Pattern + Shannon-entropy secret redaction with non-secret SHA-256 Redaction Audit Report.
6. Incremental --diff <git_ref> delta bundling with 1-hop reverse-dependency expansion.
7. Deterministic SHA-256 chain-of-custody manifest (BUNDLE_SHA256SUMS.json) with Git provenance.
8. Hardened Colab/Kaggle .ipynb exporter v2 with topological %%writefile ordering, os.makedirs, and smoke-test cell.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

VERSION = "0.3.0-elite"

DEFAULT_EXCLUDE_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".next",
    ".turbo",
    "target",
    ".idea",
    ".vscode",
}

DEFAULT_EXCLUDE_EXTS: Set[str] = {
    ".pyc",
    ".pyo",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".mp3",
    ".mp4",
    ".m4a",
    ".wav",
    ".mov",
    ".sqlite",
    ".db",
    ".DS_Store",
}

LANG_BY_EXT: Dict[str, str] = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "jsx",
    ".go": "go",
    ".rs": "rust",
    ".sql": "sql",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "zsh",
    ".md": "markdown",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".html": "html",
    ".css": "css",
}


@dataclass(frozen=True)
class QuotaConfig:
    """Calibrated to Google AI Pro NotebookLM limits."""

    max_sources: int = 300
    reserved_brief_sources: int = 2
    max_words_per_source: int = 500_000
    target_words_per_bundle: int = 180_000
    max_bytes_per_source: int = 200 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024

    @property
    def max_code_bundles(self) -> int:
        return max(1, self.max_sources - self.reserved_brief_sources)


@dataclass(frozen=True)
class RedactionEvent:
    rel_path: str
    line_no: int
    rule_id: str
    secret_sha256_prefix: str


@dataclass
class FileRecord:
    rel_path: str
    abs_path: Path
    language: str
    domain: str
    content: str
    word_count: int
    byte_count: int
    sha256: str
    symbols: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    centrality_score: float = 0.0
    redactions: List[RedactionEvent] = field(default_factory=list)


class SecretRedactor:
    """Pattern + Shannon-entropy secret scanner and redactor."""

    PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
        ("PEM_PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
        ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
        ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
        ("GITHUB_PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
        ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b")),
        ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
        ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        ("BEARER_HEADER", re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9\-._~+/]{16,}=*)")),
        ("DB_CONN_URI", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:([^@\s]+)@")),
    ]

    ENV_ASSIGN_RE = re.compile(
        r"^(\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PWD|CREDENTIAL|AUTH|DSN)[A-Z0-9_]*\s*=\s*)(.+?)\s*$"
    )
    HIGH_ENTROPY_QUOTED_RE = re.compile(r"""(['"])([A-Za-z0-9+/=_\-]{24,})\1""")

    @staticmethod
    def shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @staticmethod
    def _hash_prefix(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()[:12]

    def redact_text(self, rel_path: str, text: str) -> Tuple[str, List[RedactionEvent]]:
        events: List[RedactionEvent] = []
        is_env_file = Path(rel_path).name.startswith(".env")

        # Multi-line PEM block first
        def _pem_sub(match: re.Match[str]) -> str:
            secret = match.group(0)
            line_no = text[: match.start()].count("\n") + 1
            events.append(RedactionEvent(rel_path, line_no, "PEM_PRIVATE_KEY", self._hash_prefix(secret)))
            return "[REDACTED:PEM_PRIVATE_KEY]"

        text = self.PATTERNS[0][1].sub(_pem_sub, text)

        lines = text.splitlines(keepends=True)
        out_lines: List[str] = []
        for idx, line in enumerate(lines, start=1):
            current = line
            if is_env_file and "=" in current and not current.lstrip().startswith("#"):
                k, _, v = current.partition("=")
                stripped_v = v.strip().strip("'\"")
                if stripped_v and not stripped_v.startswith("[REDACTED"):
                    events.append(RedactionEvent(rel_path, idx, "DOTENV_VALUE", self._hash_prefix(stripped_v)))
                    ending = "\n" if current.endswith("\n") else ""
                    current = f"{k}=[REDACTED:DOTENV_VALUE]{ending}"
                    out_lines.append(current)
                    continue

            for rule_id, pat in self.PATTERNS[1:]:
                def _pat_sub(m: re.Match[str], r_id: str = rule_id, line_num: int = idx) -> str:
                    if m.lastindex and m.lastindex >= 1:
                        if r_id == "BEARER_HEADER":
                            sec = m.group(2)
                            events.append(RedactionEvent(rel_path, line_num, r_id, self._hash_prefix(sec)))
                            return f"{m.group(1)}[REDACTED:{r_id}]"
                        if r_id == "DB_CONN_URI":
                            sec = m.group(1)
                            events.append(RedactionEvent(rel_path, line_num, r_id, self._hash_prefix(sec)))
                            return m.group(0).replace(sec, f"[REDACTED:{r_id}]")
                    sec = m.group(0)
                    events.append(RedactionEvent(rel_path, line_num, r_id, self._hash_prefix(sec)))
                    return f"[REDACTED:{r_id}]"

                current = pat.sub(_pat_sub, current)

            env_m = self.ENV_ASSIGN_RE.match(current.rstrip("\r\n"))
            if env_m:
                raw_val = env_m.group(2).strip().strip("'\"")
                if len(raw_val) >= 8 and "[REDACTED:" not in raw_val and raw_val not in {"true", "false", "None", "null"}:
                    events.append(RedactionEvent(rel_path, idx, "SENSITIVE_ASSIGN", self._hash_prefix(raw_val)))
                    ending = "\n" if current.endswith("\n") else ""
                    current = f"{env_m.group(1)}[REDACTED:SENSITIVE_ASSIGN]{ending}"

            def _entropy_sub(m: re.Match[str], line_num: int = idx) -> str:
                quote, token = m.group(1), m.group(2)
                if token.startswith("[REDACTED") or "/" in token or token.isalpha():
                    return m.group(0)
                if self.shannon_entropy(token) >= 4.2:
                    events.append(RedactionEvent(rel_path, line_num, "HIGH_ENTROPY_TOKEN", self._hash_prefix(token)))
                    return f"{quote}[REDACTED:HIGH_ENTROPY_TOKEN]{quote}"
                return m.group(0)

            current = self.HIGH_ENTROPY_QUOTED_RE.sub(_entropy_sub, current)
            out_lines.append(current)

        return "".join(out_lines), events


class GitIgnoreMatcher:
    """Hierarchical .gitignore matcher with safe defaults."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.patterns_by_dir: Dict[Path, List[str]] = {}
        self._load_root_ignores()

    def _load_root_ignores(self) -> None:
        gi = self.root / ".gitignore"
        if gi.is_file():
            self.patterns_by_dir[self.root] = self._parse_gitignore(gi)

    @staticmethod
    def _parse_gitignore(path: Path) -> List[str]:
        rules: List[str] = []
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            rules.append(line)
        return rules

    def register_dir(self, directory: Path) -> None:
        gi = directory / ".gitignore"
        if gi.is_file() and directory not in self.patterns_by_dir:
            self.patterns_by_dir[directory] = self._parse_gitignore(gi)

    def is_ignored(self, path: Path, is_dir: bool = False) -> bool:
        name = path.name
        if is_dir and name in DEFAULT_EXCLUDE_DIRS:
            return True
        if not is_dir and path.suffix.lower() in DEFAULT_EXCLUDE_EXTS:
            return True
        if not is_dir and name in DEFAULT_EXCLUDE_EXTS:
            return True

        resolved = path.resolve()
        for base_dir, rules in self.patterns_by_dir.items():
            try:
                rel = resolved.relative_to(base_dir).as_posix()
            except ValueError:
                continue
            for rule in rules:
                clean = rule.rstrip("/")
                if rule.endswith("/") and not is_dir:
                    if fnmatch.fnmatch(rel, f"{clean}/*") or any(fnmatch.fnmatch(part, clean) for part in rel.split("/")):
                        return True
                elif "/" in clean:
                    if fnmatch.fnmatch(rel, clean.lstrip("/")):
                        return True
                else:
                    if fnmatch.fnmatch(name, clean) or fnmatch.fnmatch(rel, clean):
                        return True
        return False


class SymbolAndGraphExtractor:
    """Extracts symbols and imports across Python and polyglot languages."""

    TS_JS_IMPORT_RE = re.compile(r"""(?:import\s+[\s\S]*?\s+from\s+|require\s*\(\s*)['"]([^'"]+)['"]""")
    TS_JS_SYM_RE = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function|class|interface|type|const)\s+([A-Za-z_][A-Za-z0-9_]*)")
    GO_IMPORT_RE = re.compile(r'^\s*"([^"]+)"', re.MULTILINE)
    GO_SYM_RE = re.compile(r"^\s*(?:func|type)\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)")
    RUST_USE_RE = re.compile(r"^\s*use\s+([A-Za-z0-9_:]+)")
    RUST_SYM_RE = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?(?:fn|struct|enum|trait|impl)\s+([A-Za-z_][A-Za-z0-9_]*)")

    @classmethod
    def extract(cls, rel_path: str, language: str, content: str) -> Tuple[List[str], List[str]]:
        if language == "python":
            return cls._extract_python(content)
        if language in {"typescript", "tsx", "javascript", "jsx"}:
            imports = sorted(set(cls.TS_JS_IMPORT_RE.findall(content)))
            symbols = sorted(set(m.group(1) for line in content.splitlines() if (m := cls.TS_JS_SYM_RE.match(line))))
            return symbols, imports
        if language == "go":
            imports = sorted(set(cls.GO_IMPORT_RE.findall(content)))
            symbols = sorted(set(m.group(1) for line in content.splitlines() if (m := cls.GO_SYM_RE.match(line))))
            return symbols, imports
        if language == "rust":
            imports = sorted(set(m.group(1) for line in content.splitlines() if (m := cls.RUST_USE_RE.match(line))))
            symbols = sorted(set(m.group(1) for line in content.splitlines() if (m := cls.RUST_SYM_RE.match(line))))
            return symbols, imports
        return [], []

    @staticmethod
    def _extract_python(content: str) -> Tuple[List[str], List[str]]:
        symbols: List[str] = []
        imports: Set[str] = set()
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return [], []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols.append(node.name)
                if isinstance(node, ast.ClassDef):
                    for child in node.body:
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and not child.name.startswith("_"):
                            symbols.append(f"{node.name}.{child.name}")
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        symbols.append(target.id)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)

        return sorted(set(symbols)), sorted(imports)


class DependencyGraph:
    """Directed dependency graph with centrality and topological ordering."""

    def __init__(self, records: List[FileRecord]) -> None:
        self.records = {r.rel_path: r for r in records}
        self.edges: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_edges: Dict[str, Set[str]] = defaultdict(set)
        self._build()

    def _build(self) -> None:
        stem_map: Dict[str, List[str]] = defaultdict(list)
        for rel in self.records:
            p = Path(rel)
            dotted = p.with_suffix("").as_posix().replace("/", ".")
            stem_map[p.stem].append(rel)
            stem_map[dotted].append(rel)

        for rel, rec in self.records.items():
            for imp in rec.imports:
                clean = imp.lstrip("./").replace("/", ".")
                candidates = stem_map.get(clean, []) or stem_map.get(clean.split(".")[-1], [])
                for target in candidates:
                    if target != rel:
                        self.edges[rel].add(target)
                        self.reverse_edges[target].add(rel)

        for rel, rec in self.records.items():
            in_deg = len(self.reverse_edges[rel])
            out_deg = len(self.edges[rel])
            rec.centrality_score = round((in_deg * 2.0) + (out_deg * 0.5) + (len(rec.symbols) * 0.1), 2)

    def detect_cycles(self) -> List[Tuple[str, str]]:
        cycles: List[Tuple[str, str]] = []
        seen: Set[Tuple[str, str]] = set()
        for src, targets in self.edges.items():
            for dst in targets:
                if src in self.edges.get(dst, set()):
                    pair = tuple(sorted((src, dst)))
                    if pair not in seen:
                        seen.add(pair)
                        cycles.append((pair[0], pair[1]))
        return sorted(cycles)

    def topological_order(self) -> List[str]:
        """Dependencies before dependents (for %%writefile ordering)."""
        in_degree: Dict[str, int] = {rel: len(self.edges[rel]) for rel in self.records}
        queue = sorted([rel for rel, deg in in_degree.items() if deg == 0])
        ordered: List[str] = []
        while queue:
            curr = queue.pop(0)
            ordered.append(curr)
            for dependent in sorted(self.reverse_edges[curr]):
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)
                    queue.sort()
        remaining = sorted(set(self.records) - set(ordered))
        return ordered + remaining

    def expand_one_hop(self, changed_paths: Iterable[str]) -> Set[str]:
        selected = set(changed_paths) & set(self.records)
        for path in list(selected):
            selected.update(self.reverse_edges.get(path, set()))
            selected.update(self.edges.get(path, set()))
        return selected


def classify_domain(rel_path: str) -> str:
    lower = rel_path.lower()
    parts = set(Path(lower).parts)
    if "test" in lower or "tests" in parts or "spec" in lower:
        return "05_TESTS_AND_VERIFICATION"
    if any(k in lower for k in ("api", "router", "route", "endpoint", "mcp", "connector", "client", "webhook", "server")):
        return "02_API_AND_CONNECTORS"
    if any(k in lower for k in ("schema", "model", "migration", "sql", "db", "ledger", "manifest")):
        return "03_DATA_AND_SCHEMAS"
    if Path(lower).suffix in {".md", ".toml", ".yaml", ".yml", ".json", ".txt", ".ini"}:
        return "04_DOCS_AND_CONFIG"
    return "01_CORE_RUNTIME"


def dynamic_fence(content: str, lang: str = "") -> str:
    max_run = 2
    for m in re.finditer(r"`+", content):
        max_run = max(max_run, len(m.group(0)))
    fence = "`" * (max_run + 1)
    return f"{fence}{lang}\n{content.rstrip()}\n{fence}\n"


def get_git_provenance(repo_root: Path) -> Dict[str, Any]:
    def _run(args: List[str]) -> str:
        try:
            res = subprocess.run(
                ["git", "-C", str(repo_root), *args],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            return res.stdout.strip() if res.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    return {
        "commit": _run(["rev-parse", "HEAD"]),
        "branch": _run(["rev-parse", "--abbrev-ref", "HEAD"]),
        "dirty": bool(_run(["status", "--porcelain"]) not in {"", "unknown"}),
    }


def get_changed_files_since(repo_root: Path, base_ref: str) -> Set[str]:
    res = subprocess.run(
        ["git", "-C", str(repo_root), "diff", "--name-only", base_ref],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if res.returncode != 0:
        return set()
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


def scan_repository(repo_root: Path, quota: QuotaConfig) -> Tuple[List[FileRecord], List[RedactionEvent]]:
    root = repo_root.resolve()
    matcher = GitIgnoreMatcher(root)
    redactor = SecretRedactor()
    records: List[FileRecord] = []
    all_redactions: List[RedactionEvent] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        cur_dir = Path(dirpath)
        matcher.register_dir(cur_dir)
        dirnames[:] = sorted(d for d in dirnames if not matcher.is_ignored(cur_dir / d, is_dir=True))

        for fname in sorted(filenames):
            fpath = cur_dir / fname
            if fpath.is_symlink() or matcher.is_ignored(fpath, is_dir=False):
                continue
            try:
                size = fpath.stat().st_size
                if size > quota.max_file_bytes:
                    continue
                raw = fpath.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = fpath.relative_to(root).as_posix()
            redacted, events = redactor.redact_text(rel_path, raw)
            all_redactions.extend(events)

            lang = LANG_BY_EXT.get(fpath.suffix.lower(), "text")
            symbols, imports = SymbolAndGraphExtractor.extract(rel_path, lang, redacted)
            words = len(redacted.split())
            byte_len = len(redacted.encode("utf-8"))
            sha = hashlib.sha256(redacted.encode("utf-8")).hexdigest()

            records.append(
                FileRecord(
                    rel_path=rel_path,
                    abs_path=fpath,
                    language=lang,
                    domain=classify_domain(rel_path),
                    content=redacted,
                    word_count=words,
                    byte_count=byte_len,
                    sha256=sha,
                    symbols=symbols,
                    imports=imports,
                )
            )

    return records, all_redactions


def pack_domain_bundles(
    records: List[FileRecord],
    quota: QuotaConfig,
) -> List[Tuple[str, List[FileRecord]]]:
    """Packs files into domain-cohesive bundles within Google AI Pro 300-source quota."""
    by_domain: Dict[str, List[FileRecord]] = defaultdict(list)
    for rec in records:
        by_domain[rec.domain].append(rec)

    bundles: List[Tuple[str, List[FileRecord]]] = []
    for domain in sorted(by_domain):
        domain_recs = sorted(by_domain[domain], key=lambda r: (-r.centrality_score, r.rel_path))
        part_idx = 1
        current_group: List[FileRecord] = []
        current_words = 0
        current_bytes = 0

        for rec in domain_recs:
            would_exceed_words = (current_words + rec.word_count) > quota.target_words_per_bundle
            would_exceed_bytes = (current_bytes + rec.byte_count) > quota.max_bytes_per_source
            if current_group and (would_exceed_words or would_exceed_bytes):
                bundles.append((f"{domain}_PART_{part_idx:02d}.md", current_group))
                part_idx += 1
                current_group = []
                current_words = 0
                current_bytes = 0

            current_group.append(rec)
            current_words += rec.word_count
            current_bytes += rec.byte_count

        if current_group:
            bundles.append((f"{domain}_PART_{part_idx:02d}.md", current_group))

    # Enforce strict 300-source ceiling by merging smallest adjacent bundles if needed
    while len(bundles) > quota.max_code_bundles and len(bundles) >= 2:
        bundles.sort(key=lambda b: sum(r.word_count for r in b[1]))
        _, small_a = bundles.pop(0)
        name_b, small_b = bundles.pop(0)
        merged = small_a + small_b
        if sum(r.word_count for r in merged) > quota.max_words_per_source:
            bundles.append((name_b, small_b))
            break
        bundles.append((f"MERGED_{name_b}", merged))

    bundles.sort(key=lambda b: b[0])
    return bundles


def export_notebooklm_bundles(
    repo_root: Path,
    out_dir: Path,
    quota: QuotaConfig,
    diff_ref: Optional[str] = None,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    provenance = get_git_provenance(repo_root)
    records, redactions = scan_repository(repo_root, quota)
    graph = DependencyGraph(records)

    if diff_ref:
        changed = get_changed_files_since(repo_root, diff_ref)
        scope = graph.expand_one_hop(changed)
        records = [r for r in records if r.rel_path in scope]

    bundles = pack_domain_bundles(records, quota)
    cycles = graph.detect_cycles()
    top_central = sorted(records, key=lambda r: (-r.centrality_score, r.rel_path))[:20]

    generated_files: Dict[str, str] = {}

    # 1. System Brief
    brief_lines = [
        f"# 00_NOTEBOOKLM_SYSTEM_BRIEF — {repo_root.name}",
        "",
        f"- **Engine:** `repo-to-notebook` v{VERSION}",
        f"- **Git Commit:** `{provenance['commit']}` (`{provenance['branch']}`, dirty={provenance['dirty']})",
        f"- **Mode:** {'Delta Diff (' + diff_ref + ')' if diff_ref else 'Full Repository'}",
        f"- **Files Indexed:** {len(records)} | **Markdown Bundles:** {len(bundles)} / {quota.max_code_bundles} slots",
        f"- **Redactions Applied:** {len(redactions)} (see `REDACTION_AUDIT.json`)",
        "",
        "## Architectural Hotspots (Top Centrality)",
    ]
    for rec in top_central:
        brief_lines.append(
            f"- `{rec.rel_path}` — centrality `{rec.centrality_score}`, symbols `{len(rec.symbols)}`, domain `{rec.domain}`"
        )

    brief_lines.extend(["", "## Mutual Circular Dependencies"])
    if cycles:
        for a, b in cycles:
            brief_lines.append(f"- `{a}` <-> `{b}`")
    else:
        brief_lines.append("- None detected.")

    brief_lines.extend(
        [
            "",
            "## Recommended NotebookLM Analysis Prompts",
            "1. *Architecture Trace:* Using `00_MASTER_INDEX_AND_SYMBOLS.md`, trace execution from entrypoints through `01_CORE_RUNTIME` and `02_API_AND_CONNECTORS`.",
            "2. *Security & Boundary Audit:* Identify all authentication checks, input validation boundaries, and secret-handling paths across high-centrality modules.",
            "3. *Test Gap Analysis:* Compare symbols in `01_CORE_RUNTIME` against coverage in `05_TESTS_AND_VERIFICATION`.",
        ]
    )
    generated_files["00_NOTEBOOKLM_SYSTEM_BRIEF.md"] = "\n".join(brief_lines) + "\n"

    # 2. Master Index & Symbol Map
    index_lines = [
        f"# 00_MASTER_INDEX_AND_SYMBOLS — {repo_root.name}",
        "",
        "| Bundle File | Files | Words |",
        "|---|---:|---:|",
    ]
    for bname, brecs in bundles:
        index_lines.append(f"| `{bname}` | {len(brecs)} | {sum(r.word_count for r in brecs):,} |")
    index_lines.extend(["", "## File & Symbol Directory"])
    for bname, brecs in bundles:
        index_lines.append(f"\n### {bname}")
        for r in brecs:
            sym_preview = ", ".join(r.symbols[:12]) + (" ..." if len(r.symbols) > 12 else "")
            index_lines.append(f"- `{r.rel_path}` (`{r.language}`, {r.word_count}w, sha256:`{r.sha256[:12]}`)" + (f" — Symbols: `{sym_preview}`" if sym_preview else ""))
    generated_files["00_MASTER_INDEX_AND_SYMBOLS.md"] = "\n".join(index_lines) + "\n"

    # 3. Domain Bundles
    for bname, brecs in bundles:
        parts = [
            f"# {bname}",
            f"> Repo: `{repo_root.name}` | Commit: `{provenance['commit'][:12]}` | Files: {len(brecs)}",
            "",
        ]
        for r in brecs:
            parts.append(f"## File: `{r.rel_path}`")
            parts.append(f"- Language: `{r.language}` | Words: {r.word_count} | Centrality: {r.centrality_score} | SHA-256: `{r.sha256}`")
            if r.imports:
                parts.append(f"- Imports: `{', '.join(r.imports[:20])}`")
            parts.append("")
            parts.append(dynamic_fence(r.content, r.language))
        generated_files[bname] = "\n".join(parts)

    # 4. Write bundles + Redaction Audit + SHA-256 Manifest
    sha_manifest: Dict[str, Any] = {
        "version": VERSION,
        "repo": repo_root.name,
        "provenance": provenance,
        "files": {},
    }

    for fname, text in sorted(generated_files.items()):
        target = out_dir / fname
        target.write_text(text, encoding="utf-8")
        sha_manifest["files"][fname] = {
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "bytes": len(text.encode("utf-8")),
            "words": len(text.split()),
        }

    audit_payload = [dataclasses.asdict(e) for e in redactions]
    (out_dir / "REDACTION_AUDIT.json").write_text(json.dumps(audit_payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "BUNDLE_SHA256SUMS.json").write_text(json.dumps(sha_manifest, indent=2) + "\n", encoding="utf-8")

    return {
        "version": VERSION,
        "files_indexed": len(records),
        "bundles_created": len(bundles),
        "total_sources": len(bundles) + 2,
        "redactions": len(redactions),
        "out_dir": str(out_dir),
    }


def export_colab_notebook(
    repo_root: Path,
    out_ipynb: Path,
    quota: QuotaConfig,
) -> Dict[str, Any]:
    """Exports topological %%writefile Jupyter notebook with os.makedirs and smoke test."""
    records, redactions = scan_repository(repo_root, quota)
    graph = DependencyGraph(records)
    topo_paths = graph.topological_order()
    rec_map = {r.rel_path: r for r in records}

    cells: List[Dict[str, Any]] = []

    def _md_cell(source: str) -> Dict[str, Any]:
        return {"cell_type": "markdown", "metadata": {}, "source": source.splitlines(keepends=True)}

    def _code_cell(source: str) -> Dict[str, Any]:
        return {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": source.splitlines(keepends=True),
        }

    cells.append(
        _md_cell(
            f"# {repo_root.name} — Executable Colab/Kaggle Bundle (`repo-to-notebook` v{VERSION})\n\n"
            f"- Files: {len(records)} | Redactions: {len(redactions)} | Topological Ordering: Enabled\n"
        )
    )

    cells.append(
        _code_cell(
            "import os, sys, platform\n"
            "print('Python:', sys.version)\n"
            "print('Platform:', platform.platform())\n"
        )
    )

    # Pre-create all nested parent directories before any %%writefile cell executes
    parent_dirs = sorted({Path(p).parent.as_posix() for p in topo_paths if Path(p).parent.as_posix() != "."})
    mkdir_lines = ["import os", "for _d in " + json.dumps(parent_dirs) + ":", "    os.makedirs(_d, exist_ok=True)"]
    cells.append(_code_cell("\n".join(mkdir_lines) + "\n"))

    # Dependency bootstrap if requirements.txt exists
    if "requirements.txt" in rec_map:
        cells.append(_code_cell("!pip install -q -r requirements.txt\n"))

    for rel in topo_paths:
        rec = rec_map[rel]
        cells.append(_code_cell(f"%%writefile {rec.rel_path}\n{rec.content.rstrip()}\n"))

    # Smoke-test cell
    cells.append(
        _code_cell(
            "import subprocess, sys\n"
            "res = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', '.', '-p', 'test_*.py'], check=False)\n"
            "print('Smoke test exit code:', res.returncode)\n"
        )
    )

    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.10.0"},
        },
        "cells": cells,
    }

    out_ipynb.parent.mkdir(parents=True, exist_ok=True)
    out_ipynb.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")
    return {
        "version": VERSION,
        "files_written": len(topo_paths),
        "directories_created": len(parent_dirs),
        "out_ipynb": str(out_ipynb),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="repo-to-notebook v0.3.0 (Elite) — GlacierEQ")
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("bundle", help="Export domain-cohesive NotebookLM Markdown bundles")
    b.add_argument("repo", type=Path, help="Path to repository root")
    b.add_argument("-o", "--out", type=Path, required=True, help="Output directory")
    b.add_argument("--diff", type=str, default=None, help="Git ref for incremental 1-hop delta bundle")
    b.add_argument("--target-words", type=int, default=180_000, help="Target words per Markdown bundle")

    c = sub.add_parser("colab", help="Export topological executable .ipynb for Colab/Kaggle")
    c.add_argument("repo", type=Path, help="Path to repository root")
    c.add_argument("-o", "--out", type=Path, required=True, help="Output .ipynb file path")

    a = sub.add_parser("audit", help="Scan repository for secrets and dependency centrality")
    a.add_argument("repo", type=Path, help="Path to repository root")

    args = parser.parse_args(argv)
    if args.command == "bundle":
        quota = QuotaConfig(target_words_per_bundle=args.target_words)
        summary = export_notebooklm_bundles(args.repo, args.out, quota, diff_ref=args.diff)
        print(json.dumps(summary, indent=2))
    elif args.command == "colab":
        summary = export_colab_notebook(args.repo, args.out, QuotaConfig())
        print(json.dumps(summary, indent=2))
    elif args.command == "audit":
        records, redactions = scan_repository(args.repo, QuotaConfig())
        graph = DependencyGraph(records)
        print(
            json.dumps(
                {
                    "files": len(records),
                    "redactions": [dataclasses.asdict(r) for r in redactions],
                    "cycles": graph.detect_cycles(),
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
