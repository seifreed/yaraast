# yaraast

A Python library for parsing and manipulating YARA rules using Abstract Syntax Trees.

## Features

- **100% YARA Parsing Success**: Parses all production YARA files (273,683+ rules tested)
- **YARA-L 2.0 Support**: Full support for Google Chronicle detection rules (891/891 files)
- **YARA-X Support**: Compatible with YARA-X syntax and features
- **Automatic Dialect Detection**: Context-aware detection distinguishes YARA, YARA-L, and YARA-X
- **Advanced Features**:
  - Hex nibble wildcards (`4?`, `?5`, `??`)
  - Regex modifiers (`/i`, `/m`, `/s`, `/g`)
  - VirusTotal LiveHunt module support
  - Wildcard string sets (`$a*`, `any of ($prefix*)`)
  - Negative integers in metadata
  - Extended `of...in` operator with ranges (`N of ($a*) in (start..end)`)
  - PE exports with regex patterns (`pe.exports(/pattern/)`)
  - Comment-aware hex string parsing
  - Streaming parser for large files (100MB+ threshold)
  - ClamAV syntax detection

## Installation

```bash
pip install yaraast
```

## Quick Start

```python
from yaraast import Parser
from yaraast.unified_parser import UnifiedParser

# Parse YARA rules with automatic dialect detection
yara_code = """
rule example {
    meta:
        author = "Security Team"
        version = 1
    strings:
        $hex = { 4D 5A 90 00 }
        $str = "malware" wide
    condition:
        $hex at 0 and $str
}
"""

# Option 1: Direct parser (when you know it's standard YARA)
parser = Parser(yara_code)
ast = parser.parse()

# Option 2: Unified parser with auto-detection (recommended)
ast = UnifiedParser.parse_string(yara_code)

# Access rule components
rule = ast.rules[0]
print(f"Rule: {rule.name}")
print(f"Strings: {len(rule.strings)}")
print(f"Condition: {rule.condition}")
```

## Advanced Usage

### Automatic Dialect Detection

The UnifiedParser automatically detects YARA, YARA-L, and YARA-X dialects:

```python
from yaraast.unified_parser import UnifiedParser

# Parse file with automatic detection
ast = UnifiedParser.parse_file("rules.yar")

# Or parse string
ast = UnifiedParser.parse_string(yara_code)

# Force specific dialect if needed
from yaraast.dialects import YaraDialect
ast = UnifiedParser.parse_file("rules.yar", dialect=YaraDialect.YARA)
```

### Streaming Parser for Large Files

For very large YARA files (100MB+), use streaming mode:

```python
from yaraast.unified_parser import UnifiedParser

# Automatically uses streaming for files > 100MB
ast = UnifiedParser.parse_file("large_ruleset.yar")

# Force streaming for smaller files
ast = UnifiedParser.parse_file("rules.yar", force_streaming=True)

# Custom threshold (in MB)
ast = UnifiedParser.parse_file("rules.yar", streaming_threshold_mb=50)
```

### Lenient Parsing Mode

For files with mixed YARA/ClamAV syntax:

```python
from yaraast import Parser

# Enable lenient mode to skip invalid patterns
parser = Parser(yara_code, lenient=True)
ast = parser.parse()

# Check for skipped patterns
if parser.errors:
    print(f"Skipped {len(parser.errors)} invalid patterns")
```

### Working with YARA-L

```python
from yaraast.yaral import YaraLParser

yaral_code = """
rule detect_suspicious_activity {
    meta:
        author = "Threat Intel"
    events:
        $e.metadata.event_type = "NETWORK_CONNECTION"
        $e.target.port = 443
    condition:
        $e
}
"""

parser = YaraLParser(yaral_code)
ast = parser.parse()
```

### VirusTotal Module Support

Full support for VirusTotal LiveHunt and Retrohunt rules:

```python
from yaraast import Parser

# Parse rules using VirusTotal module
vt_rule = """
import "vt"

rule vt_livehunt_example {
    meta:
        description = "Detect files based on VT intelligence"
    condition:
        vt.metadata.new_file and
        vt.metadata.analysis_stats.malicious > 5 and
        vt.metadata.file_type == vt.FileType.PE_EXE
}
"""

parser = Parser(vt_rule)
ast = parser.parse()

# Access VT module usage
print(f"Uses VT module: {'vt' in [imp.module for imp in ast.imports]}")
```

Supported VT module features:
- `vt.metadata.*` - File metadata and analysis statistics
- `vt.behaviour.*` - Behavioral analysis data
- `vt.net.*` - Network activity indicators
- All VirusTotal Intelligence operators and functions

### Visitor Pattern

```python
from yaraast import Parser
from yaraast.visitor import BaseVisitor

class RuleCollector(BaseVisitor):
    def __init__(self):
        self.rule_names = []

    def visit_rule(self, node):
        self.rule_names.append(node.name)
        super().visit_rule(node)

ast = Parser(yara_code).parse()
collector = RuleCollector()
collector.visit(ast)
print(f"Found rules: {collector.rule_names}")
```

## Language Support

### YARA Features
- ✅ All YARA syntax and operators
- ✅ Hex strings with wildcards and jumps
- ✅ Regular expressions with modifiers
- ✅ String modifiers (ascii, wide, nocase, fullword, xor, base64)
- ✅ All condition operators and expressions
- ✅ Module imports (pe, elf, math, hash, vt, etc.)
- ✅ PE exports with regex patterns (`pe.exports(/pattern/)`)
- ✅ Extended `of...in` ranges (`N of ($a*) in (start..end)`)
- ✅ Private and global rules
- ✅ Include directives
- ✅ Comments inside hex strings

### YARA-L 2.0 Features
- ✅ Event matching and correlation
- ✅ Outcome sections
- ✅ Time windows and aggregations
- ✅ Match sections
- ✅ Complex boolean expressions
- ✅ Chronicle-specific functions

### YARA-X Features
- ✅ New syntax elements
- ✅ Enhanced type system
- ✅ Compatibility mode

## Testing

Verified with production rulesets:
- **ClamAV**: 223,261 rules
- **YARA Master Collection**: 31,463 rules
- **Community Rules**: 11,331 rules
- **Google Chronicle**: 891 YARA-L rules

## Performance

- Parses 273,683+ rules across 14 files
- 337 comprehensive tests (100% passing)
- Handles files up to 91MB
- Streaming mode for files > 100MB
- ~1,800 rules/second on large files (30MB+)

## Requirements

- Python >= 3.13
- click >= 8.1.0
- rich >= 13.0.0
- attrs >= 23.0.0
- PyYAML >= 6.0.0

## Optional Dependencies

```bash
# LSP support
pip install yaraast[lsp]

# libyara integration
pip install yaraast[libyara]

# Performance optimization
pip install yaraast[performance]

# Visualization
pip install yaraast[visualization]

# All features
pip install yaraast[all]
```

## CLI Usage

```bash
# Parse YARA file
yaraast parse rules.yar

# Validate syntax
yaraast validate rules.yar

# Pretty-print with formatting
yaraast format rules.yar

# Start LSP server
yaraast lsp
```

## License

MIT License - see LICENSE file for details

## Author

Marc Rivero (mriverolopez@gmail.com)

## Links

- **PyPI**: https://pypi.org/project/yaraast/
- **GitHub**: https://github.com/mriverolopez/yaraast
- **Documentation**: https://yaraast.readthedocs.io/
