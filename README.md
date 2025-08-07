# YARAAST - YARA Abstract Syntax Tree

A powerful Python library and CLI tool for parsing, analyzing, and manipulating
YARA rules through Abstract Syntax Tree (AST) representations.

**NOW WITH YARA-L SUPPORT!** Parse and analyze YARA-L rules for Google Chronicle
alongside standard YARA and YARA-X formats.

**Author:** Marc Rivero | @seifreed  
**Email:** <mriverolopez@gmail.com>  
**GitHub:** [https://github.com/seifreed/yaraast](https://github.com/seifreed/yaraast)

## Features

- **Multi-Dialect Support**: Parse YARA, YARA-X, and YARA-L rules
- **Automatic Dialect Detection**: Intelligently detects rule format
- Parse YARA rules into a structured AST with multiple output formats
- Analyze rules for optimization opportunities and best practices
- Format and prettify YARA files with customizable styles
- Validate syntax and semantic correctness
- Generate comprehensive metrics and visualizations (complexity, strings, dependencies)
- Support for large rulesets with thousands of rules
- Extensible visitor pattern for custom analysis
- Performance benchmarking and streaming for huge files
- AST-based diff comparison between YARA files
- LibYARA integration for compilation and scanning
- Fluent API for programmatic rule construction
- Roundtrip testing for serialization fidelity
- Multi-file workspace analysis with dependency resolution
- Export/import AST in JSON/YAML/Protobuf formats

### YARA-L Support (NEW!)

- Parse Google Chronicle YARA-L 2.0 rules
- Support for UDM (Unified Data Model) fields
- Event correlation and time windows
- Aggregation functions (count, sum, max, min, etc.)
- Reference lists and CIDR expressions
- Outcome sections with conditional logic
- Match sections with sliding windows

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
yaraast parse rule.yar                    # Default output (auto-detect dialect)
yaraast parse rule.yar --format json      # JSON representation
yaraast parse rule.yar --format yaml      # YAML representation
yaraast parse rule.yar --format tree      # Tree visualization

# Parse with specific dialect
yaraast parse rule.yar --dialect yara     # Force standard YARA
yaraast parse rule.yar --dialect yara-l   # Force YARA-L parser
yaraast parse rule.yar --dialect auto     # Auto-detect (default)
```

#### validate - Syntax Validation

```bash
# Validate YARA file syntax
yaraast validate ruleset.yar              # Check for syntax errors
yaraast validate *.yar                    # Validate multiple files
```

#### format - Code Formatting

```bash
# Format YARA files with consistent style
yaraast format input.yar output.yar       # Format to new file
yaraast format --help                     # See formatting options
```

#### fmt - In-place Formatting (like black)

```bash
# Format YARA files in place
yaraast fmt rule.yar                      # Format with default style
yaraast fmt --style compact rule.yar      # Use compact style
yaraast fmt --style readable rule.yar     # Use readable style
yaraast fmt --check rule.yar              # Check if formatting needed
```

### Analysis Commands

#### analyze - AST-Based Analysis

```bash
# Optimization analysis
yaraast analyze optimize ruleset.yar      # Find optimization opportunities

# Best practices analysis
yaraast analyze best-practices rule.yar   # Check best practices
yaraast analyze best-practices -v rule.yar # Verbose output with suggestions
```

#### metrics - Rule Metrics and Visualization

```bash
# Complexity metrics
yaraast metrics complexity rule.yar       # Analyze rule complexity

# String analysis
yaraast metrics strings rule.yar          # Analyze string patterns

# Visualizations
yaraast metrics tree rule.yar --output tree.html    # HTML tree visualization
yaraast metrics graph rule.yar            # Generate dependency graph
yaraast metrics patterns rule.yar         # String pattern analysis
yaraast metrics report rule.yar           # Comprehensive report
```

#### semantic - Semantic Validation

```bash
# Semantic validation beyond syntax
yaraast semantic rule.yar                 # Check semantic correctness
yaraast semantic *.yar --quiet            # Check multiple files quietly
yaraast semantic rule.yar --strict        # Treat warnings as errors
```

### Development Commands

#### serialize diff - Compare YARA Files

```bash
# Show differences between files
yaraast serialize diff old.yar new.yar    # AST-based diff comparison
```

#### roundtrip - Serialization Testing

```bash
# Test AST serialization/deserialization
yaraast roundtrip test rule.yar           # Verify round-trip consistency
yaraast roundtrip test rule.yar -v        # Verbose output
yaraast roundtrip serialize rule.yar      # Serialize to JSON/YAML
yaraast roundtrip deserialize ast.json    # Deserialize back to YARA
yaraast roundtrip pretty rule.yar         # Pretty print with style options
yaraast roundtrip pipeline rule.yar       # CI/CD pipeline format
```

#### serialize - Import/Export AST

```bash
# Serialize AST for storage or transmission
yaraast serialize export rule.yar --format json  # Export to JSON
yaraast serialize export rule.yar --format yaml  # Export to YAML
yaraast serialize import-ast ast.json     # Import from serialized format
yaraast serialize info rule.yar           # Show AST structure info
yaraast serialize validate ast.json       # Validate serialized format
```

### Performance Commands

#### performance - Large Ruleset Tools

```bash
# Performance analysis and optimization
yaraast performance stream large.yar       # Stream processing for huge files
yaraast performance optimize rules/        # Get optimization recommendations
```

#### performance-check - Performance Analysis

```bash
# Check for performance issues
yaraast performance-check rule.yar        # Analyze performance issues
```

#### bench - Benchmarking Suite

```bash
# Run benchmarks
yaraast bench rule.yar                    # Default benchmarks
yaraast bench rule.yar --operations parse # Benchmark parsing only
yaraast bench rule.yar --iterations 10    # Custom iterations
yaraast bench *.yar --compare             # Compare performance across files
```

### Integration Commands

#### libyara - LibYARA Integration

```bash
# Scan with LibYARA integration
yaraast libyara scan rule.yar target      # Scan files
yaraast libyara scan rule.yar target --optimize  # Use optimized compilation
yaraast libyara scan rule.yar target --stats     # Show scan statistics

# Optimize rules for LibYARA
yaraast libyara optimize rule.yar         # Optimize and show results
yaraast libyara optimize rule.yar --show-optimizations  # Detailed view
```

#### workspace - Multi-File Analysis

```bash
# Analyze directories with multiple YARA files
yaraast workspace analyze /path/to/rules  # Analyze all files in directory
yaraast workspace graph /path/to/rules    # Generate dependency graph
yaraast workspace resolve main.yar        # Resolve all includes
```

### Advanced Commands

#### fluent - Fluent API Examples

```bash
# Demonstrate fluent API usage
yaraast fluent examples                   # Show example rules
yaraast fluent conditions                 # Demonstrate condition builders
yaraast fluent string-patterns            # Show string pattern builders
yaraast fluent template                   # Generate rule template
yaraast fluent transformations            # Show AST transformations
```

#### optimize - Rule Optimization

```bash
# Optimize YARA rules
yaraast optimize input.yar output.yar     # Optimize rules
yaraast optimize rule.yar optimized.yar --show-changes  # Show what changed
```

## Usage Examples

### Working with YARA-L

```python
from yaraast.unified_parser import UnifiedParser
from yaraast.dialects import YaraDialect

# Auto-detect and parse YARA-L rules
yaral_code = """
rule suspicious_activity {
    events:
        $e.metadata.event_type = "USER_LOGIN"
        $e.security_result.action = "BLOCK"
    match:
        $userid over 5m
    condition:
        #e > 5
}
"""

parser = UnifiedParser(yaral_code)
print(f"Detected dialect: {parser.get_dialect()}")  # YaraDialect.YARA_L

ast = parser.parse()
# Process YARA-L AST...
```

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
  analyze            AST-based analysis commands
  bench              Performance benchmarks for AST operations
  fluent             Fluent API demonstrations and examples
  fmt                Format YARA file in-place (like black for Python)
  format             Format a YARA file to new file
  libyara            LibYARA integration for scanning and optimization
  metrics            Analyze and visualize YARA metrics
  optimize           Optimize YARA rules for better performance
  parse              Parse YARA file and output in various formats
  performance        Performance tools for large rule collections
  performance-check  Analyze YARA rules for performance issues
  roundtrip          Round-trip serialization and pretty printing
  semantic           Perform semantic validation on YARA files
  serialize          AST serialization for export/import
  validate           Validate YARA file for syntax errors
  workspace          Multi-file analysis and dependency resolution
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
- Optional: protobuf for binary serialization

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
