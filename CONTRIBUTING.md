# Contributing

## Setup

```bash
python3.13 -m venv venv
source venv/bin/activate
python -m pip install -e ".[dev,libyara,lsp,visualization,serialization,performance]"
```

Every behavior change needs a focused regression test. Run that test first,
then the full suite when the affected surface is not narrow:

```bash
pytest tests/path/to/test_file.py
pytest
ruff check .
mypy .
black --check .
bandit -r yaraast
```

Keep pull requests focused. Update `CHANGELOG.md`, `MIGRATING.md`, and
`docs/compatibility.md` when a public contract changes. Do not commit generated
caches, benchmark output, local paths, credentials, or agent instructions.

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
