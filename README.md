# YARA AST - Abstract Syntax Tree for YARA Rules

A high-performance Python 3.13+ library for parsing, analyzing, and manipulating YARA rules. Designed to handle everything from single rules to massive rulesets with thousands of rules.

**Author:** Marc Rivero | @seifreed  
**Repository:** [https://github.com/seifreed/yaraast](https://github.com/seifreed/yaraast)

## Overview

YARA AST provides a complete Abstract Syntax Tree implementation for YARA rules, enabling programmatic analysis, transformation, and generation of YARA rules. The library is built for performance and can efficiently process large-scale rule collections used in production environments.

## Key Features

- **Full YARA Language Support**: Complete implementation of YARA language features including modules, includes, and all condition operators
- **High Performance**: Optimized for processing thousands of rules with streaming and parallel processing capabilities
- **AST Manipulation**: Modify, optimize, and transform YARA rules programmatically
- **Semantic Validation**: Type checking and semantic analysis to catch errors before runtime
- **Rule Analysis**: Detect unused strings, circular dependencies, and optimization opportunities
- **Multiple Output Formats**: JSON, YAML, Protocol Buffers, and formatted YARA output
- **YARA-X Compatible**: Support for the new YARA-X parser features

## Installation

```bash
pip install yaraast
```

### From Source

```bash
git clone https://github.com/seifreed/yaraast
cd yaraast
pip install -e .
```

## Usage Examples

### Basic Parsing

```python
from yaraast import Parser

# Parse a single rule
yara_code = '''
rule detect_malware {
    meta:
        author = "Security Team"
        description = "Detects specific malware pattern"
    strings:
        $mz = { 4D 5A }
        $string = "malicious"
    condition:
        $mz at 0 and $string
}
'''

parser = Parser()
ast = parser.parse(yara_code)

# Access rule properties
for rule in ast.rules:
    print(f"Rule: {rule.name}")
    print(f"Strings: {len(rule.strings)}")
    print(f"Meta: {rule.meta}")
```

### Processing Large Rulesets

```python
from yaraast import Parser
from pathlib import Path

# Parse a file with thousands of rules
parser = Parser()
ast = parser.parse_file("large_ruleset.yar")

# Analyze the ruleset
print(f"Total rules: {len(ast.rules)}")
print(f"Total imports: {len(ast.imports)}")
print(f"Total includes: {len(ast.includes)}")

# Process rules efficiently
for rule in ast.rules:
    # Perform analysis on each rule
    if len(rule.strings) > 100:
        print(f"Complex rule found: {rule.name} with {len(rule.strings)} strings")
```

### Rule Analysis and Optimization

```python
from yaraast import Parser, RuleAnalyzer, OptimizationAnalyzer

# Parse rules
parser = Parser()
ast = parser.parse_file("rules.yar")

# Analyze rules for issues
analyzer = RuleAnalyzer()
results = analyzer.analyze(ast)

# Check for unused strings
for rule_name, analysis in results['string_analysis'].items():
    unused = analysis.get('unused', [])
    if unused:
        print(f"Rule '{rule_name}' has {len(unused)} unused strings")

# Find optimization opportunities
optimizer = OptimizationAnalyzer()
opt_report = optimizer.analyze(ast)

for suggestion in opt_report.suggestions:
    print(f"{suggestion.rule_name}: {suggestion.description}")
```

### Building Rules Programmatically

```python
from yaraast.builder import RuleBuilder, ConditionBuilder

# Create a new rule using the builder API
rule = (RuleBuilder("detect_suspicious_behavior")
    .add_meta("author", "Security Team")
    .add_meta("date", "2025-01-01")
    .add_string("$sus1", "suspicious.exe")
    .add_string("$sus2", { "48 8B 05 ?? ?? ?? ??" })
    .add_tag("malware")
    .add_tag("trojan")
    .set_condition("any of them")
    .build())

# Generate YARA code
from yaraast import CodeGenerator
generator = CodeGenerator()
yara_output = generator.generate(rule)
print(yara_output)
```

### AST Transformation

```python
from yaraast import Parser, ASTVisitor, CodeGenerator

class StringPrefixTransformer(ASTVisitor):
    """Add prefix to all string identifiers"""
    
    def visit_string_definition(self, node):
        node.identifier = f"$prefix_{node.identifier[1:]}"
        return node

# Parse and transform
parser = Parser()
ast = parser.parse_file("original.yar")

transformer = StringPrefixTransformer()
transformed_ast = transformer.visit(ast)

# Generate modified rules
generator = CodeGenerator()
output = generator.generate(transformed_ast)
```

### CLI Usage

The library includes a comprehensive command-line interface:

```bash
# Parse and validate rules
yaraast parse ruleset.yar --format tree
yaraast validate ruleset.yar

# Analyze rules for issues
yaraast analyze best-practices ruleset.yar
yaraast analyze optimize ruleset.yar

# Convert between formats
yaraast serialize export ruleset.yar --format json -o rules.json
yaraast serialize import rules.json --format yara -o ruleset.yar

# Process large collections
yaraast performance batch /path/to/rules --operations parse complexity
yaraast performance stream large_ruleset.yar --memory-limit 500
```

## Performance Considerations

The library is designed to handle large-scale deployments:

- **Streaming Parser**: Process rules one at a time with minimal memory usage
- **Batch Processing**: Efficiently process thousands of files in parallel
- **Memory Optimization**: Configurable memory limits and garbage collection
- **Parallel Analysis**: Multi-threaded analysis for large rule collections

Example for processing thousands of rules:

```python
from yaraast.performance import StreamingParser

# Process large ruleset with limited memory
parser = StreamingParser(max_memory_mb=500)

for result in parser.parse_directory("/path/to/rules", pattern="*.yar"):
    if result.status == "success":
        print(f"Processed: {result.file_path}")
    else:
        print(f"Error in {result.file_path}: {result.error}")
```

## Advanced Features

### Semantic Validation

```python
from yaraast import Parser
from yaraast.types import SemanticValidator

parser = Parser()
ast = parser.parse_file("rules.yar")

validator = SemanticValidator()
result = validator.validate(ast)

if not result.is_valid:
    for error in result.errors:
        print(f"Error: {error}")
```

### Dependency Analysis

```python
from yaraast.analysis import DependencyAnalyzer

analyzer = DependencyAnalyzer()
deps = analyzer.analyze(ast)

# Find circular dependencies
for cycle in deps['circular_dependencies']:
    print(f"Circular dependency: {' -> '.join(cycle)}")

# Get rule dependencies
for rule_name, dependencies in deps['dependencies'].items():
    print(f"{rule_name} depends on: {', '.join(dependencies)}")
```

## Architecture

The library follows a modular architecture:

- **Parser**: Lexical and syntactic analysis producing AST
- **AST Nodes**: Strongly-typed representation of YARA constructs
- **Visitor Pattern**: Traversal and transformation framework
- **Analyzers**: Rule analysis and optimization modules
- **Code Generators**: Output formatting and serialization
- **Performance Module**: Large-scale processing capabilities

## Requirements

- Python 3.13 or higher
- Optional: yara-python for cross-validation with libyara

## Contributing

Contributions are welcome! Please check the GitHub repository for guidelines.

## License

This project is licensed under the MIT License with an attribution requirement.

### License Summary

- **Free to use**: You can use this software freely for any purpose (commercial or non-commercial)
- **Attribution required**: You must include attribution to the original author when using this software
- **Attribution format**: "YARA AST by Marc Rivero (@seifreed) - https://github.com/seifreed/yaraast"

### Full License

See the [LICENSE](LICENSE) file for the complete license text.

Copyright (c) 2025 Marc Rivero (@seifreed)
