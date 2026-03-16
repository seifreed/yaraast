"""Services for YARA-L CLI commands (logic without IO)."""

from __future__ import annotations

from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.optimizer import YaraLOptimizer
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.validator import YaraLValidator


def parse_yaral(content: str, enhanced: bool):
    """Parse YARA-L content using selected parser."""
    if enhanced:
        return EnhancedYaraLParser(content).parse()
    return YaraLParser(content).parse()


def parse_yaral_best_effort(content: str):
    """Parse using enhanced parser, fallback to standard."""
    return EnhancedYaraLParser(content).parse()


def validate_yaral(ast):
    """Validate YARA-L AST and return errors/warnings."""
    validator = YaraLValidator()
    return validator.validate(ast)


def optimize_yaral(ast):
    """Optimize YARA-L AST and return (optimized_ast, stats)."""
    optimizer = YaraLOptimizer()
    return optimizer.optimize(ast)


def generate_yaral(ast) -> str:
    """Generate YARA-L code from AST."""
    return YaraLGenerator().generate(ast)


def format_yaral_code(code: str) -> str:
    """Format YARA-L code with proper indentation."""
    lines = code.split("\n")
    formatted_lines = []
    indent = 0
    section_keywords = [
        "rule",
        "meta",
        "events",
        "match",
        "condition",
        "outcome",
        "options",
    ]
    for line in lines:
        stripped = line.strip()
        if not stripped:
            formatted_lines.append("")
            continue
        formatted_line, indent = _format_line(stripped, indent, section_keywords)
        formatted_lines.append(formatted_line)
    return "\n".join(formatted_lines)


def _format_line(stripped: str, indent: int, section_keywords: list) -> tuple[str, int]:
    """Format a single line and return the formatted line and new indent level."""
    if stripped.endswith("{"):
        return ("  " * indent + stripped, indent + 1)
    if stripped.startswith("}"):
        new_indent = max(0, indent - 1)
        return ("  " * new_indent + stripped, new_indent)
    if stripped.endswith(":"):
        line = "  " * indent + stripped
        new_indent = indent + 1 if not stripped.startswith("rule") else indent
        return (line, new_indent)
    if stripped and not any(stripped.startswith(s) for s in section_keywords):
        return ("  " * max(1, indent) + stripped, indent)

    new_indent = 1 if stripped in section_keywords[1:] else indent
    return ("  " * new_indent + stripped, new_indent)


def compare_semantic(ast1, ast2) -> bool:
    """Return True if semantically equivalent."""
    generator = YaraLGenerator()
    return generator.generate(ast1) == generator.generate(ast2)


def compare_structural(ast1, ast2) -> list[str]:
    """Return list of structural differences."""
    if len(ast1.rules) != len(ast2.rules):
        return [f"Different number of rules: {len(ast1.rules)} vs {len(ast2.rules)}"]
    differences = []
    for rule1, rule2 in zip(ast1.rules, ast2.rules, strict=False):
        if rule1.name != rule2.name:
            differences.append(f"Rule name: {rule1.name} vs {rule2.name}")
    return differences
