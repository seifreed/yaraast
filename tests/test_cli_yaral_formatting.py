"""Tests for YARA-L CLI formatting helpers."""

from __future__ import annotations

from yaraast.cli.yaral_services import _format_line
from yaraast.cli.yaral_services import format_yaral_code as _format_yaral_code


def test_format_line_handles_sections_and_braces() -> None:
    section_keywords = ["rule", "meta", "events", "match", "condition", "outcome", "options"]

    formatted, indent = _format_line("rule demo {", 0, section_keywords)
    assert formatted.startswith("rule demo {")
    assert indent == 1

    formatted, indent = _format_line("meta:", indent, section_keywords)
    assert formatted.strip() == "meta:"
    assert indent >= 1

    formatted, indent = _format_line("}", indent, section_keywords)
    assert formatted.strip() == "}"
    assert indent >= 0


def test_format_yaral_code_indents_sections() -> None:
    code = 'rule demo {\nmeta:\nauthor = "me"\ncondition:\n#e > 0\n}'
    formatted = _format_yaral_code(code)

    assert "rule demo {" in formatted
    assert "  meta:" in formatted
    assert '    author = "me"' in formatted
    assert "  condition:" in formatted
