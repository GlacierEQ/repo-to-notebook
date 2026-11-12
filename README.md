# repo-to-notebook (v0.3.0-elite)

**GlacierEQ Repository-to-NotebookLM & Colab/Kaggle Engine**

Calibrated for Google AI Pro NotebookLM quotas (**300 sources/notebook**, **500,000 words/source**, **200 MB/source**) and hardened for executable Google Colab / Kaggle `.ipynb` exports.

## Features

1. **Multi-Language AST & Structural Symbol Extraction:** Full Python `ast` parsing plus structural symbol/import extraction for TypeScript, TSX, JavaScript, JSX, Go, Rust, SQL, and Shell.
2. **Directed Dependency Graph (DAG) & Centrality Ranking:** Cross-file import/reverse-import graph, circular dependency detection, and centrality scoring so architectural hotspots lead every bundle.
3. **Domain-Cohesive Semantic Packing:** Organizes files into `01_CORE_RUNTIME`, `02_API_AND_CONNECTORS`, `03_DATA_AND_SCHEMAS`, `04_DOCS_AND_CONFIG`, and `05_TESTS_AND_VERIFICATION` within the 300-source ceiling.
4. **NotebookLM System Brief & Master Index:** Generates `00_NOTEBOOKLM_SYSTEM_BRIEF.md` and `00_MASTER_INDEX_AND_SYMBOLS.md`.
5. **Pattern + Shannon-Entropy Secret Redaction:** Inline redaction for PEM keys, Google AI (`AIza...`), GitHub (`ghp_`, `github_pat_`), AWS, Stripe, Slack, JWTs, Bearer headers, DB URIs, and `.env` values, plus `REDACTION_AUDIT.json`.
6. **Incremental Delta Mode (`--diff <git_ref>`):** Re-bundles modified files plus their 1-hop imports and dependents.
7. **Deterministic Cryptographic Manifest:** Emits `BUNDLE_SHA256SUMS.json` with Git provenance and SHA-256 hashes.
8. **Hardened Colab / Kaggle Exporter v2:** Topologically orders `%%writefile` cells, pre-creates nested directories via `os.makedirs(..., exist_ok=True)`, bootstraps `requirements.txt`, and appends a `unittest` smoke-test cell.

## Usage

```bash
# Run unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Export domain-cohesive NotebookLM bundles
python3 repo_to_notebook_elite.py bundle . -o ./notebooklm_out

# Export incremental delta bundle since main
python3 repo_to_notebook_elite.py bundle . -o ./notebooklm_delta --diff main

# Export topological Colab/Kaggle notebook
python3 repo_to_notebook_elite.py colab . -o ./dist/repo_bundle.ipynb

# Run secret & dependency centrality audit
python3 repo_to_notebook_elite.py audit .
```
