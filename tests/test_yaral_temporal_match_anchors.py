"""Regression tests for YARA-L temporal match anchors."""

from __future__ import annotations

import pytest

from yaraast.yaral.ast_nodes import MatchVariable, TimeWindow
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.parser import YaraLParser


def test_yaral_parser_accepts_after_temporal_anchor() -> None:
    source = """
rule temporal_after {
  events:
    $create.metadata.event_type = "USER_CREATION"
    $login.metadata.event_type = "USER_LOGIN"
  match:
    $login over 48h after $create
  condition:
    $create and $login
}
"""

    parsed = YaraLParser(source).parse()

    match = parsed.rules[0].match
    assert match is not None
    variable = match.variables[0]
    assert variable.variable == "login"
    assert variable.time_window == TimeWindow(duration=48, unit="h")
    assert variable.temporal_anchor == "after"
    assert variable.anchor_variable == "create"


def test_enhanced_yaral_parser_accepts_before_temporal_anchor() -> None:
    source = """
rule temporal_before {
  events:
    $grant.metadata.event_type = "GRANT"
    $login.metadata.event_type = "LOGIN"
  match:
    $login over 2h before $grant
  condition:
    $grant and $login
}
"""

    parser = EnhancedYaraLParser(source)
    parsed = parser.parse()

    assert parser.errors == []
    match = parsed.rules[0].match
    assert match is not None
    variable = match.variables[0]
    assert variable.variable == "login"
    assert variable.time_window == TimeWindow(duration=2, unit="h")
    assert variable.temporal_anchor == "before"
    assert variable.anchor_variable == "grant"


def test_yaral_generator_preserves_temporal_anchor() -> None:
    node = MatchVariable(
        variable="userid",
        time_window=TimeWindow(duration=1, unit="h", modifier="every"),
        temporal_anchor="after",
        anchor_variable="create",
    )

    assert YaraLGenerator().visit_match_variable(node) == "$userid over every 1h after $create"


def test_match_variable_rejects_anchor_without_variable() -> None:
    node = MatchVariable(
        variable="userid",
        time_window=TimeWindow(duration=1, unit="h"),
        temporal_anchor="after",
    )

    with pytest.raises(TypeError, match="anchor_variable"):
        node.validate_structure()


def test_match_variable_rejects_invalid_temporal_anchor() -> None:
    node = MatchVariable(
        variable="userid",
        time_window=TimeWindow(duration=1, unit="h"),
        temporal_anchor="during",
        anchor_variable="create",
    )

    with pytest.raises(ValueError, match="temporal_anchor"):
        node.validate_structure()
