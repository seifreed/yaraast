# Changelog

All notable changes are documented here. This project follows semantic
versioning.

## Unreleased

### Added

- Stable root `parse`, `parse_file`, and `format` APIs.
- Python 3.11 through 3.14 support and the `py.typed` marker.
- Pinned libyara/YARA-X differential conformance and a published dialect matrix.
- Effective coverage and Graphviz integration gates.

### Changed

- Standard MIT licensing and a single package-metadata version source.
- The LSP now requires the pygls 2 / lsprotocol 2025 API.
- Static typing now checks all CLI modules and no inline policy suppressions remain.

### Removed

- Legacy LSP dependency fallbacks, import repair, and obsolete package-root exports.
- Generated LSP caches and developer-local paths from tracked artifacts.

## 1.0.1 - 2026-03-28

Last release from the 1.x contract. See [MIGRATING.md](MIGRATING.md) before
upgrading to 2.0.
