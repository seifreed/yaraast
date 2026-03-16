from __future__ import annotations

from yaraast.yaral.ast_nodes import MatchSection, MatchVariable, TimeWindow
from yaraast.yaral.validator import YaraLValidator


def test_validate_match_section_empty_warns() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r1"

    validator._validate_match_section(MatchSection())

    assert any("Match section has no variables" in warn.message for warn in validator.warnings)


def test_validate_match_section_duplicates_invalid_and_large_window() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r2"

    section = MatchSection(
        variables=[
            MatchVariable(variable="user", time_window=TimeWindow(0, "x")),
            MatchVariable(variable="user", time_window=TimeWindow(45, "days")),
        ]
    )

    validator._validate_match_section(section)

    assert any("Duplicate match variable" in err.message for err in validator.errors)
    assert any("Invalid time unit" in err.message for err in validator.errors)
    assert any("Time window duration must be positive" in err.message for err in validator.errors)
    assert any("Large time window" in warn.message for warn in validator.warnings)


def test_visit_yaral_match_section_variable_and_time_window() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r3"

    section = MatchSection(variables=[MatchVariable(variable="e", time_window=TimeWindow(5, "m"))])
    validator.visit_yaral_match_section(section)
    assert "e" in validator.defined_match_vars

    validator.visit_yaral_match_variable(
        MatchVariable(variable="manual", time_window=TimeWindow(1, "h"))
    )
    assert "manual" in validator.defined_match_vars

    validator.visit_yaral_time_window(TimeWindow(1, "fortnights"))
    assert any("Invalid time unit 'fortnights'" in err.message for err in validator.errors)
