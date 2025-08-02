# YARA AST - Abstract Syntax Tree for YARA Rules

A complete Python 3.13+ library for parsing, analyzing, optimizing, and generating YARA rules with advanced features and YARA-X compatibility.

## Features

### 🔴 Critical Features (Implemented)
1. **Fluent Builder Pattern** - Fluent API for programmatically building YARA rules
2. **Advanced Hex Strings** - Support for nibbles (F?, ?5), open jumps ([4-], [-8], [-]) and nested alternatives
3. **YARA Modules** - Full access to module attributes (pe.sections[0].name)
4. **Type System** - Complete semantic validation with type inference

### 🟡 Important Features (Implemented)
5. **Comment Preservation** - Maintains comments in the AST and regenerates them
6. **Rule Analysis** - Detects unused strings, analyzes dependencies between rules
7. **Advanced Formatting** - Multiple formatting styles, spacing configuration
8. **Missing Operators** - Support for `defined`, `iequals`, `icontains` and arrays in expressions

### 🟢 Additional Features (Implemented)
9. **Optimization** - Expression simplification, dead code elimination
10. **YARA-X** - Compatibility and migration tools for the new parser

## Installation

```bash
pip install -e .
```

## Usage

### As a Library

```python
from yaraast import Parser, CodeGenerator

# Parse YARA rules
yara_code = '''
rule example_rule {
    meta:
        author = "Security Team"
    strings:
        $a = "malware"
        $b = { 48 65 6C 6C 6F }
    condition:
        $a or $b
}
'''

parser = Parser(yara_code)
ast = parser.parse()

# Generate code from AST
generator = CodeGenerator()
output = generator.generate(ast)
print(output)
```

### Using the CLI

```bash
# Parse and display as tree
yaraast parse rule.yar --format tree

# Validate YARA file
yaraast validate rule.yar

# Format YARA file
yaraast format input.yar output.yar

# Convert to JSON
yaraast parse rule.yar --format json -o ast.json
```

## Architecture

### AST Node Types

- **YaraFile**: Root node containing imports, includes, and rules
- **Rule**: Individual YARA rule with modifiers, tags, meta, strings, and condition
- **StringDefinition**: Base class for string definitions (plain, hex, regex)
- **Expression**: Base class for all expressions in conditions
- **Condition**: Special expressions used in rule conditions

### Visitor Pattern

The library implements the visitor pattern for AST traversal:

```python
from yaraast import ASTVisitor

class RuleCounter(ASTVisitor[int]):
    def __init__(self):
        self.count = 0
    
    def visit_rule(self, node):
        self.count += 1
        return self.count

counter = RuleCounter()
counter.visit(ast)
print(f"Total rules: {counter.count}")
```

## Examples

See the `examples/` directory for more usage examples:
- `parse_file.py`: Basic parsing example
- `transform_ast.py`: AST transformation example
- `custom_visitor.py`: Custom visitor implementation

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black yaraast/
ruff check yaraast/

# Type checking
mypy yaraast/
```

## License

MIT License
