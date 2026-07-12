# Contributing

Thanks for contributing to SBOM Risk Analyzer.

## Development setup

```bash
git clone <your-fork-url>
cd sbom-risk-analyzer
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . pytest
python -m pytest -q
```

## Pull requests

- Keep changes focused and include tests for behavior changes or bug fixes.
- Preserve offline-first behavior; network access must be explicit or clearly documented.
- Do not commit generated SBOMs, OSV caches, credentials, or private project data.
- Run `python -m pytest -q` before opening a pull request.

## Adding ecosystem support

Add parsers in `sbom_risk/parsers.py`, input discovery in `sbom_risk/discovery.py`, and OSV ecosystem mapping in `sbom_risk/osv.py`. Include representative parser and graph tests.
