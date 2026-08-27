# yaraast

`yaraast` parses, analyzes, formats, and transforms YARA, YARA-X, and YARA-L
source code through a typed Python API and command-line interface.

## Quick start

```python
import yaraast

document = yaraast.parse("rule example { condition: true }")
print(document.ast.rules[0].name)
print(yaraast.generate(document))
```

The parsed document keeps the detected or requested dialect. Pass an explicit
`dialect=` to `generate` only when converting to another supported output
dialect.

See the [public API](api.md) and [compatibility matrix](compatibility.md) for
the supported contracts and reference engines.

For installation, CLI workflows, resource limits, and a runnable example, see
[Getting Started](getting-started.md).
