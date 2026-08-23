# Migrating to 2.0

YaraAST 2.0 intentionally removes legacy compatibility behavior. Upgrade in a
clean environment and use the documented public API:

```python
import yaraast

document = yaraast.parse("rule example { condition: true }")
document = yaraast.parse_file("rules.yar", dialect="auto")
formatted = yaraast.format_canonical("rule example { condition: true }")
```

## Required Changes

- Use Python 3.11 or newer.
- Replace the former root `format()` call with `format_canonical()`; use
  `rewrite_lossless()` for byte-preserving edits and `generate()` for new ASTs.
- Import parser implementations from their namespaces, such as
  `yaraast.parser`, `yaraast.yarax`, or `yaraast.yaral`; do not import internal
  classes from the package root.
- Read the installed version from `yaraast.__version__` or package metadata.
- Install LSP support with `yaraast[lsp]`; pygls 1 compatibility is removed.
- Treat automatic dialect detection as best effort. Pass `dialect=` for a fixed
  grammar and review [the support matrix](docs/compatibility.md).
- Regenerate serialized artifacts when their declared schema version changes;
  no implicit migration layer is provided.

Run the formatter and conformance tests over representative rules before
deploying the upgrade.
