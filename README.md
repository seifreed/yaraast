# YARAAST - YARA Abstract Syntax Tree

A powerful Python library and CLI tool for parsing, analyzing, and manipulating
YARA rules through Abstract Syntax Tree (AST) representations.

**Author:** Marc Rivero | @seifreed  
**Email:** <mriverolopez@gmail.com>  
**GitHub:** [https://github.com/seifreed/yaraast](https://github.com/seifreed/yaraast)

## Features

- Parse YARA rules into a structured AST
- Analyze rules for optimization opportunities
- Format and prettify YARA files
- Validate syntax and semantic correctness
- Support for large rulesets with thousands of rules
- Extensible visitor pattern for custom analysis
- Performance benchmarking and metrics
- Diff comparison between YARA files
- LibYARA integration for compilation and scanning

## Installation

```bash
pip install yaraast
```

### From Source

```bash
git clone https://github.com/seifreed/yaraast
cd yaraast
pip install -r requirements.txt
pip install -e .
```

## Quick Start

```bash
# Get help
yaraast --help

# Show version
yaraast --version
```

## Command Reference

### Core Commands

#### parse - Parse and Output YARA Files

```bash
# Parse and output in different formats
yaraast parse rule.yar                    # Default output
yaraast parse rule.yar --format json      # JSON representation
yaraast parse rule.yar --format yaml      # YAML representation
yaraast parse rule.yar --format tree      # Tree visualization
```

#### validate - Syntax Validation

```bash
# Validate YARA file syntax
yaraast validate ruleset.yar              # Check for syntax errors
yaraast validate *.yar                    # Validate multiple files
```

#### format - Code Formatting

```bash
# Format YARA files (like black for Python)
yaraast format input.yar                  # Format in place
yaraast format input.yar -o output.yar    # Format to new file
yaraast format *.yar                      # Format multiple files
```

### Analysis Commands

#### analyze - AST-Based Analysis

```bash
# Optimization analysis
yaraast analyze optimize ruleset.yar      # Find optimization opportunities
yaraast analyze optimize --detailed rule.yar  # Detailed suggestions

# Best practices analysis
yaraast analyze best-practices rule.yar   # Check best practices

# Complexity analysis
yaraast analyze complexity rule.yar       # Analyze rule complexity

# Security analysis

yaraast analyze security ruleset.yar      # Security best practices check
```

#### metrics - Rule Metrics and Visualization

```bash
# Generate metrics
yaraast metrics rule.yar                  # Basic metrics

yaraast metrics --detailed ruleset.yar    # Detailed statistics
yaraast metrics --export-csv metrics.csv rule.yar  # Export to CSV
```

#### semantic - Semantic Validation

```bash
# Semantic validation beyond syntax
yaraast semantic validate rule.yar        # Check semantic correctness
yaraast semantic check-references rule.yar  # Verify all references

yaraast semantic detect-duplicates ruleset.yar  # Find duplicate rules
```

### Development Commands

#### diff - Compare YARA Files

```bash

# Show differences between files
yaraast diff old.yar new.yar              # Basic diff
yaraast diff --semantic old.yar new.yar   # Logical vs stylistic changes
yaraast diff --ignore-comments old.yar new.yar  # Ignore comment changes
```

#### roundtrip - Serialization Testing

```bash
# Test AST serialization/deserialization
yaraast roundtrip test rule.yar           # Verify round-trip consistency
yaraast roundtrip pretty rule.yar         # Pretty print after round-trip
```

#### serialize - Import/Export AST

```bash

# Serialize AST for storage or transmission
yaraast serialize export rule.yar -o ast.json  # Export to JSON
yaraast serialize import ast.json -o rule.yar  # Import from JSON
yaraast serialize convert rule.yar --to yaml   # Convert between formats
```

### Performance Commands

#### performance - Large Ruleset Tools

```bash
# Performance analysis and optimization
yaraast performance benchmark ruleset.yar  # Benchmark parsing speed
yaraast performance profile ruleset.yar    # Profile memory usage
yaraast performance stream large.yar       # Stream processing for huge files
yaraast performance batch /path/to/rules   # Batch process directory
```

#### bench - Benchmarking Suite

```bash
# Run benchmarks
yaraast bench parse rule.yar              # Benchmark parsing
yaraast bench all ruleset.yar             # Run all benchmarks
yaraast bench compare old.yar new.yar     # Compare performance
```

### Integration Commands

#### libyara - LibYARA Integration

```bash
# Compile and scan with LibYARA
yaraast libyara compile rule.yar          # Compile rules
yaraast libyara scan rule.yar target.exe  # Scan files
yaraast libyara verify rule.yar           # Verify LibYARA compatibility
```

#### workspace - Multi-File Analysis

```bash
# Workspace management for projects
yaraast workspace init                    # Initialize workspace
yaraast workspace add rules/*.yar         # Add files to workspace
yaraast workspace analyze                 # Analyze entire workspace
yaraast workspace report                  # Generate workspace report

```

### Advanced Commands

#### fluent - Fluent API Examples

```bash
# Demonstrate fluent API usage
yaraast fluent examples                   # Show API examples
yaraast fluent build                      # Interactive rule builder
yaraast fluent convert rule.yar           # Convert to fluent API code
```

#### fmt - Advanced Formatting

```bash
# Advanced formatting options (like black)
yaraast fmt rule.yar                      # Auto-format with defaults
yaraast fmt --line-length 100 rule.yar    # Custom line length
yaraast fmt --style compact rule.yar      # Compact style
yaraast fmt --check rule.yar              # Check if formatting needed
```

## Usage Examples

### As a Python Library

```python
from yaraast import Parser
from yaraast.visitors import OptimizationAnalyzer

# Parse YARA rules
parser = Parser()
with open('ruleset.yar', 'r') as f:
    ast = parser.parse(f.read())

# Analyze for optimizations
analyzer = OptimizationAnalyzer()
analyzer.visit(ast)
suggestions = analyzer.get_suggestions()

for suggestion in suggestions:
    print(f"{suggestion.rule}: {suggestion.message}")
```

### Batch Processing

```bash
# Process multiple files
for file in *.yar; do
    yaraast validate "$file" && \
    yaraast format "$file" && \
    yaraast analyze optimize "$file" > "${file%.yar}_report.txt"
done
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Validate YARA Rules
  run: |
    pip install yaraast
    yaraast validate rules/*.yar
    yaraast analyze security rules/*.yar
```

### Large Ruleset Analysis

```bash
# Analyze massive rulesets efficiently
yaraast performance stream huge_ruleset.yar | \
    yaraast analyze optimize - | \
    yaraast metrics --export-csv analysis.csv -
```

## Complete Command List

```text
Commands:
  analyze      AST-based analysis commands
  bench        Performance benchmarks for AST operations
  diff         Show AST-based diff highlighting logical vs stylistic changes
  fluent       Fluent API demonstrations and examples
  fmt          Format YARA file using AST-based formatting (like black for Python)
  format       Format a YARA file with consistent style
  libyara      LibYARA integration commands for compilation and scanning
  metrics      Analyze and visualize YARA AST metrics
  parse        Parse a YARA file and output in various formats
  performance  Performance tools for large YARA rule collections
  roundtrip    Round-trip serialization and pretty printing commands
  semantic     Perform semantic validation on YARA files
  serialize    AST serialization commands for export/import and versioning
  validate     Validate a YARA file for syntax errors
  workspace    Workspace commands for multi-file analysis
```

## Real-World Usage

### Processing Production Rulesets

The tool has been tested with production rulesets containing thousands of rules:

```bash
# Example: Analyzing a 10,000+ rule collection
$ yaraast analyze optimize master_yara.yar

Optimization Analysis: master_yara.yar

   Optimization
  Opportunities
┏━━━━━━━━┳━━━━━━━┓
┃ Impact ┃ Count ┃
┡━━━━━━━━╇━━━━━━━┩
│ High   │     0 │
│ Medium │  8184 │
│ Low    │  5962 │
└────────┴───────┘

Found 14146 optimization suggestions
```

### Command Chaining

Many commands support piping and chaining:

```bash
# Parse, optimize, and format
yaraast parse rule.yar | \
    yaraast analyze optimize - | \
    yaraast format - > optimized.yar

# Validate and generate report
yaraast validate ruleset.yar && \
    yaraast metrics --detailed ruleset.yar > report.txt
```

## Output Formats

Most commands support multiple output formats:

- **text** - Human-readable output (default)
- **json** - JSON for programmatic processing
- **yaml** - YAML for configuration files
- **csv** - CSV for spreadsheet analysis
- **tree** - Tree visualization for structure
- **html** - HTML reports with styling

```bash
# Examples
yaraast parse rule.yar --format json
yaraast metrics rule.yar --format csv
yaraast analyze optimize rule.yar --format html > report.html
```

## Python Module Usage

The tool can be run as a Python module:

```bash
# Run as module
python -m yaraast --help
python -m yaraast analyze optimize rule.yar

# In Python scripts
from yaraast import Parser
from yaraast.cli import cli

# Use the parser
parser = Parser()
ast = parser.parse(yara_code)

# Or invoke CLI programmatically
cli(['analyze', 'optimize', 'rule.yar'])
```

<https://github.com/seifreed/yaraast>

## Requirements

- Python 3.13 or higher
- Dependencies: click, rich, attrs, PyYAML
- Optional: yara-python for LibYARA integration

## License

This project is licensed under the MIT License with an attribution requirement.

### License Summary

- **Free to use**: You can use this software freely for any purpose
  (commercial or non-commercial)
- **Attribution required**: You must include attribution to the original author
  when using this software
- **Attribution format**: "YARA AST by Marc Rivero (@seifreed) -
  <https://github.com/seifreed/yaraast>"

### Full License

See the [LICENSE](LICENSE) file for the complete license text.

Copyright (c) 2025 Marc Rivero (@seifreed)
