#!/usr/bin/env python3
"""Unit tests for repo-to-notebook v0.3.0 (Elite)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from repo_to_notebook_elite import (
    DependencyGraph,
    QuotaConfig,
    SecretRedactor,
    dynamic_fence,
    export_colab_notebook,
    export_notebooklm_bundles,
)


class TestRepoToNotebookElite(unittest.TestCase):
    def test_secret_redaction_preserves_context_and_audits(self) -> None:
        redactor = SecretRedactor()
        # Construct a non-credential test token matching the Google-key shape.
        synthetic_key = "AIza" + ("A" * 35)
        sample = 'API_KEY = "' + synthetic_key + '"\nprint("ok")\n'
        cleaned, events = redactor.redact_text("config.py", sample)
        self.assertNotIn(synthetic_key, cleaned)
        self.assertIn("[REDACTED:GOOGLE_API_KEY]", cleaned)
        self.assertIn('print("ok")', cleaned)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0].rule_id, "GOOGLE_API_KEY")

    def test_dotenv_redaction(self) -> None:
        redactor = SecretRedactor()
        cleaned, events = redactor.redact_text(".env.local", "SUPABASE_SERVICE_ROLE_KEY=supersecretvalue12345\n")
        self.assertNotIn("supersecretvalue12345", cleaned)
        self.assertIn("[REDACTED:DOTENV_VALUE]", cleaned)
        self.assertEqual(events[0].rule_id, "DOTENV_VALUE")

    def test_dynamic_fence_escapes_nested_backticks(self) -> None:
        content = "```python\nprint(1)\n```\n"
        fenced = dynamic_fence(content, "markdown")
        self.assertTrue(fenced.startswith("````markdown\n"))
        self.assertTrue(fenced.endswith("````\n"))

    def test_bundle_and_colab_export_with_nested_dirs_and_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "sample_repo"
            (repo / "src" / "core").mkdir(parents=True)
            (repo / "tests").mkdir(parents=True)

            (repo / "src" / "core" / "engine.py").write_text(
                'def run_engine():\n    return "ok"\n', encoding="utf-8"
            )
            (repo / "src" / "app.py").write_text(
                "from core.engine import run_engine\n\ndef main():\n    return run_engine()\n",
                encoding="utf-8",
            )
            (repo / "tests" / "test_app.py").write_text(
                "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
                encoding="utf-8",
            )

            out_dir = Path(tmp) / "bundles"
            summary = export_notebooklm_bundles(repo, out_dir, QuotaConfig())
            self.assertEqual(summary["files_indexed"], 3)
            self.assertTrue((out_dir / "00_NOTEBOOKLM_SYSTEM_BRIEF.md").exists())
            self.assertTrue((out_dir / "00_MASTER_INDEX_AND_SYMBOLS.md").exists())
            self.assertTrue((out_dir / "BUNDLE_SHA256SUMS.json").exists())

            manifest = json.loads((out_dir / "BUNDLE_SHA256SUMS.json").read_text(encoding="utf-8"))
            self.assertIn("00_NOTEBOOKLM_SYSTEM_BRIEF.md", manifest["files"])

            out_ipynb = Path(tmp) / "out.ipynb"
            colab_summary = export_colab_notebook(repo, out_ipynb, QuotaConfig())
            self.assertEqual(colab_summary["files_written"], 3)
            nb = json.loads(out_ipynb.read_text(encoding="utf-8"))
            joined_cells = "\n".join("".join(c["source"]) for c in nb["cells"])
            self.assertIn("os.makedirs(_d, exist_ok=True)", joined_cells)
            self.assertIn("%%writefile src/core/engine.py", joined_cells)


if __name__ == "__main__":
    unittest.main()
