"""Additional tests for YARA-L CLI service helpers."""

from __future__ import annotations

from yaraast.cli import yaral_services as ys
from yaraast.yaral.ast_nodes import YaraLFile, YaraLRule


def test_format_yaral_code_preserves_blank_lines() -> None:
    code = 'rule test {\n\nmeta:\nname = "x"\n}\n'

    formatted = ys.format_yaral_code(code)

    assert "\n\n" in formatted


def test_format_line_handles_section_keyword_without_suffix() -> None:
    line, new_indent = ys._format_line(
        "meta", 0, ["rule", "meta", "events", "match", "condition", "outcome", "options"]
    )

    assert line == "  meta"
    assert new_indent == 1


def test_compare_structural_detects_different_rule_counts() -> None:
    ast1 = YaraLFile(rules=[YaraLRule(name="a")])
    ast2 = YaraLFile(rules=[YaraLRule(name="a"), YaraLRule(name="b")])

    diff = ys.compare_structural(ast1, ast2)

    assert diff == ["Different number of rules: 1 vs 2"]


def test_parse_yaral_best_effort_returns_ast_for_degraded_input() -> None:
    ast = ys.parse_yaral_best_effort('rule sample meta: author = "a"')

    assert isinstance(ast, YaraLFile)
