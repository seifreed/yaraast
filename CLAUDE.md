# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

yaraast is a Python library for parsing and manipulating YARA-family rules (YARA, YARA-L, YARA-X) using Abstract Syntax Trees. It provides a CLI (`yaraast`), an LSP server, and a Python API for programmatic rule construction, analysis, and transformation.

## Development Commands

```bash
# Setup
python3 -m venv venv && source venv/bin/activate
pip install -e ".[all]"          # Install with all optional deps

# Run all tests (uses pytest-xdist parallel by default)
pytest

# Run a single test file
pytest tests/test_analysis.py -x

# Run a single test
pytest tests/test_analysis.py::test_function_name -x

# Run tests without coverage/parallel (faster for debugging)
pytest tests/test_analysis.py -x --no-cov -p no:xdist

# Lint & format
ruff check yaraast/                # Lint
ruff check yaraast/ --fix          # Auto-fix
black yaraast/ tests/              # Format
isort yaraast/ tests/              # Sort imports

# Type checking
mypy yaraast/

# CLI usage
yaraast parse rules.yar
yaraast validate rules.yar
yaraast fmt rules.yar --check
```

## Architecture

### Pipeline: Text → Lexer → Parser → AST → Visitor/CodeGen

The core data flow is a classic compiler pipeline:

1. **Lexer** (`yaraast/lexer/`) — tokenizes YARA source text into a token stream
2. **Parser** (`yaraast/parser/`) — recursive descent parser consuming tokens to build AST nodes
3. **AST** (`yaraast/ast/`) — dataclass-based node hierarchy rooted at `ASTNode` (in `base.py`). `YaraFile` is the root node containing imports, includes, rules, pragmas, externs
4. **Visitor** (`yaraast/visitor/`) — three-tier pattern: `ASTVisitor` (full interface), `BaseVisitor` (default no-op implementations), `ASTTransformer` (returns modified nodes)
5. **CodeGen** (`yaraast/codegen/`) — `CodeGenerator` extends `ASTVisitor[str]` to transform AST back to YARA text

### Multi-Dialect Support

`UnifiedParser` (`yaraast/unified_parser.py`) auto-detects dialects via `yaraast/dialects/` and delegates to:
- `yaraast/parser/` — standard YARA
- `yaraast/yarax/` — YARA-X (VirusTotal)
- `yaraast/yaral/` — YARA-L (Google Chronicle)

### Key Subsystems

- **`builder/`** — Fluent API for programmatic rule construction (`RuleBuilder`, `YaraFileBuilder`, `HexStringBuilder`)
- **`analysis/`** — Rule analyzers: best practices, optimization suggestions, dependency graphs, string usage
- **`serialization/`** — AST export to JSON, YAML, Protocol Buffers; AST diffing; roundtrip testing
- **`types/`** — Type system for YARA expressions, semantic validation, module loading (pe, elf, math, etc.)
- **`lsp/`** — Language Server Protocol implementation with completion, hover, diagnostics, formatting, etc.
- **`libyara/`** — Optional integration with `yara-python` for cross-validation and scanning
- **`metrics/`** — Complexity metrics, dependency graphs, string diagrams
- **`optimization/`** — Dead code elimination, expression optimization
- **`performance/`** — Batch processing, streaming parser, memory optimization, parallel analysis
- **`cli/`** — Click-based CLI. `cli/main.py` is the entry point; commands live in `cli/commands/`; service/reporting logic split into separate modules

### Conventions

- Python 3.13+ required. All modules use `from __future__ import annotations`
- AST nodes are `@dataclass` classes with `accept()` method for visitor pattern
- Line length: 100 chars (black, isort, ruff all configured consistently)
- `C901` (function complexity) is intentionally suppressed for parser/codegen modules — complex functions are expected in recursive descent parsers
- Coverage minimum: 54% (`fail_under` in pyproject.toml)
- Test markers: `slow`, `integration`, `hypothesis`, `libyara`, `quality`
