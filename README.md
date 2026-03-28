<p align="center">
  <img src="https://img.shields.io/badge/YARAAST-YARA%20Parser%20%26%20AST-blue?style=for-the-badge" alt="YARAAST">
</p>

<h1 align="center">yaraast</h1>

<p align="center">
  <strong>Parse, analyze, and transform YARA rules with a Python AST toolkit</strong>
</p>

<p align="center">
  <a href="https://github.com/seifreed/yaraast/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/yaraast/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI"></a>
  <a href="https://github.com/seifreed/yaraast/blob/main/LICENSE"><img src="https://img.shields.io/github/license/seifreed/yaraast?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.13%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.13+">
</p>

<p align="center">
  <a href="https://github.com/seifreed/yaraast/stargazers"><img src="https://img.shields.io/github/stars/seifreed/yaraast?style=flat-square&logo=github" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/yaraast/issues"><img src="https://img.shields.io/github/issues/seifreed/yaraast?style=flat-square&logo=github" alt="GitHub Issues"></a>
  <a href="https://github.com/seifreed/yaraast/tree/main/docs"><img src="https://img.shields.io/badge/docs-GitHub-blue?style=flat-square&logo=readthedocs&logoColor=white" alt="Docs"></a>
</p>

---

## Overview

**yaraast** is a Python library for parsing and manipulating YARA-family rules using Abstract Syntax Trees (AST). It supports classic YARA, YARA-L, and YARA-X workflows with automatic dialect detection and CLI tooling.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-dialect Parsing** | Parse YARA, YARA-L, and YARA-X from files or strings |
| **Automatic Dialect Detection** | Unified parser auto-detects rule dialects |
| **AST Tooling** | Build, transform, diff, and serialize ASTs |
| **Formatting & Validation** | CLI commands for parse/format/validate workflows |
| **Streaming Support** | Parse very large files with streaming mode |
| **Ecosystem Integrations** | Optional LSP and libyara-related capabilities |

### Supported Rule Ecosystem

```text
Dialects   YARA, YARA-L, YARA-X
Parsers    Standard parser, unified parser, streaming parser
Outputs    YARA, JSON, YAML, AST tree views
Tooling    CLI, visitors, builders, serialization, semantic checks
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install yaraast
```

### From Source

```bash
git clone https://github.com/mriverolopez/yaraast.git
cd yaraast
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

---

## Quick Start

```python
from yaraast.unified_parser import UnifiedParser

yara_code = """
rule example {
    strings:
        $a = "malware" nocase
    condition:
        $a
}
"""

ast = UnifiedParser.parse_string(yara_code)
print(ast.rules[0].name)
```

---

## Usage

### Command Line Interface

```bash
# Parse and print normalized YARA
yaraast parse rules.yar

# Parse to JSON
yaraast parse rules.yar --format json

# Parse with explicit dialect
yaraast parse rules.yar --dialect yara-x

# Validate file (syntax + parse checks)
yaraast validate rules.yar

# Format file in-place (AST-based formatter)
yaraast fmt rules.yar

# Check formatting without modifying file
yaraast fmt rules.yar --check
```

### Core CLI Commands

| Command | Description |
|--------|-------------|
| `parse` | Parse a rule file and output YARA/JSON/YAML/tree |
| `validate` | Validate rules and run validation subcommands |
| `fmt` | AST-based formatter (with `--check` and `--diff`) |
| `format` | Format input into a target output file |
| `validate-syntax` | Syntax-focused validation entrypoint |
| `lsp` | Launch Language Server Protocol features |

---

## Python Library

### Unified Parsing

```python
from yaraast.unified_parser import UnifiedParser
from yaraast.dialects import YaraDialect

# Auto-detect dialect
ast = UnifiedParser.parse_file("rules.yar")

# Force specific dialect
ast = UnifiedParser.parse_file("rules.yar", dialect=YaraDialect.YARA)
```

### Direct Parser + Visitor

```python
from yaraast import Parser
from yaraast.visitor import BaseVisitor

class RuleCollector(BaseVisitor):
    def __init__(self):
        self.rules = []

    def visit_rule(self, node):
        self.rules.append(node.name)
        super().visit_rule(node)

ast = Parser(open("rules.yar", encoding="utf-8").read()).parse()
collector = RuleCollector()
collector.visit(ast)
print(collector.rules)
```

---

## Optional Dependencies

```bash
# LSP support
pip install yaraast[lsp]

# libyara integration
pip install yaraast[libyara]

# Performance tooling
pip install yaraast[performance]

# Visualization support
pip install yaraast[visualization]

# Everything
pip install yaraast[all]
```

## Runtime Docs

- LSP runtime internals: [docs/lsp-runtime.md](docs/lsp-runtime.md)
- LSP parity report: [docs/lsp-parity-report.md](docs/lsp-parity-report.md)
- Latest runtime benchmark artifact: [docs/benchmarks/lsp-runtime-latest.json](docs/benchmarks/lsp-runtime-latest.json)

---

## Requirements

- Python 3.13+
- See [pyproject.toml](pyproject.toml) for full dependency and extras list

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, quality checks, and workflow guidelines.

1. Fork the repository
2. Create a branch (`git checkout -b feature/your-change`)
3. Commit changes (`git commit -m "Add your change"`)
4. Push (`git push origin feature/your-change`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE).

**Author**
- Marc Rivero ([mriverolopez@gmail.com](mailto:mriverolopez@gmail.com))
- Repository: [github.com/mriverolopez/yaraast](https://github.com/mriverolopez/yaraast)

---

<p align="center">
  <sub>Built for malware analysis and detection engineering workflows</sub>
</p>
