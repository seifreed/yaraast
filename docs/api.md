# Public API

The supported root-level API is exported from `yaraast`.

## Parsing

```python
import yaraast

document = yaraast.parse(source, dialect="auto")
document = yaraast.parse_file("rules.yar", dialect="auto")
```

`dialect` accepts `"auto"`, `"yara"`, `"yara-x"`, or `"yara-l"`. Parsing
returns a frozen `ParsedDocument`:

| Field | Type | Meaning |
| --- | --- | --- |
| `ast` | `YaraFile \| YaraLFile` | Dialect-specific syntax tree |
| `dialect` | `"yara" \| "yara-x" \| "yara-l"` | Dialect used by the parser |
| `source_name` | `str \| None` | Input path for `parse_file`, otherwise `None` |

## Generation and formatting

```python
output = yaraast.generate(document)
converted = yaraast.generate(document, dialect="yara-x")
canonical = yaraast.format_canonical(source, dialect="auto")
```

`generate(document)` uses `document.dialect`, so parsing and generation cannot
silently disagree about the grammar. An explicit output dialect is required
when converting between dialects.

## Lossless edits

```python
edit = yaraast.SourceEdit(start=0, end=5, replacement="rule")
updated = yaraast.rewrite_lossless(source, [edit])
```

`SourceEdit` offsets are half-open UTF-8 byte ranges. Edits must be ordered by
range after validation and must not overlap or split a UTF-8 code point.

## Resource limits

`parse` and `parse_file` accept `ResourceLimits` and an optional
`CancellationToken` for bounded or cancellable processing of untrusted input.
