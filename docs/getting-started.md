# Getting Started

Install the released package:

```bash
python -m pip install yaraast
```

Parse a rule, inspect its typed AST, and generate source again:

```python
import yaraast

document = yaraast.parse("rule example { condition: true }")
assert document.ast.rules[0].name == "example"
print(yaraast.generate(document))
```

The command-line interface supports the same core workflow:

```bash
yaraast parse rule.yar
yaraast validate rule.yar
yaraast fmt --check rule.yar
yaraast parse rule.yar --dialect yara-x
```

Use `ResourceLimits` when parsing untrusted or unusually large input:

```python
from yaraast import ResourceLimits, parse

document = parse(source, limits=ResourceLimits(max_input_bytes=1_000_000))
```

Continue with the [public API](api.md), [compatibility matrix](compatibility.md),
or the runnable [quickstart example](https://github.com/seifreed/yaraast/blob/main/examples/quickstart.py).
