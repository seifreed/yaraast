# Changelog

All notable changes are documented here. This project follows semantic
versioning.

## Unreleased

### Added

- Stable root `parse` and `parse_file` APIs.
- Explicit `generate`, `format_canonical`, and byte-preserving
  `rewrite_lossless` source contracts.
- Python 3.11 through 3.14 support and the `py.typed` marker.
- Pinned libyara/YARA-X differential conformance and a published dialect matrix.
- Effective coverage and Graphviz integration gates.
- Configurable parser resource limits, deadlines, and cooperative cancellation.

### Changed

- Standard MIT licensing and a single package-metadata version source.
- The LSP now requires the pygls 2 / lsprotocol 2025 API.
- Static typing now checks all CLI modules and no inline policy suppressions remain.
- `pyproject.toml` is the only Python dependency manifest; transitive security
  pins were removed from runtime dependencies.
- The VS Code extension now declares the VS Code 1.82 API required by its
  language client and uses an audited npm lockfile.
- CLI and library parsers now apply bounded defaults; LSP parsing uses a tighter
  policy and discards partial state after cancellation or limit failures.

### Removed

- Legacy LSP dependency fallbacks, import repair, and obsolete package-root exports.
- The ambiguous root `format` name; use `format_canonical`.
- Generated LSP caches and developer-local paths from tracked artifacts.
- The divergent `requirements.txt` manifest.

## 1.0.1 - 2026-03-28

Last release from the 1.x contract. See [MIGRATING.md](MIGRATING.md) before
upgrading to 2.0.
