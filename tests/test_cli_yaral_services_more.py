"""Additional tests for YARA-L CLI service helpers."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.cli import yaral_services as ys
from yaraast.yaral.ast_nodes import YaraLFile, YaraLRule


def test_format_yaral_code_preserves_blank_lines() -> None:
    code = 'rule test {\n\nmeta:\nname = "x"\n}\n'

    formatted = ys.format_yaral_code(code)

    assert "\n\n" in formatted


@pytest.mark.parametrize("code", [None, 123, object()])
def test_format_yaral_code_rejects_invalid_code_types(code: Any) -> None:
    with pytest.raises(TypeError, match="code must be a string"):
        ys.format_yaral_code(cast(str, code))


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


def test_parse_yaral_enhanced_rejects_recovered_parser_errors() -> None:
    with pytest.raises(ValueError, match="YARA-L parse failed"):
        ys.parse_yaral(
            "rule bad { events: $e.metadata.event_type = condition: $e }",
            enhanced=True,
        )


@pytest.mark.parametrize("content", [None, 123, object()])
def test_parse_yaral_rejects_invalid_content_types(content: Any) -> None:
    with pytest.raises(TypeError, match="content must be a string"):
        ys.parse_yaral(cast(str, content), enhanced=False)


@pytest.mark.parametrize("enhanced", [None, 1, "yes", object()])
def test_parse_yaral_rejects_invalid_enhanced_types(enhanced: Any) -> None:
    with pytest.raises(TypeError, match="enhanced must be a boolean"):
        ys.parse_yaral("rule sample { condition: true }", enhanced=cast(bool, enhanced))
