from __future__ import annotations

import pytest

from yaraast.yaral.ast_nodes import (
    CIDRExpression,
    EventVariable,
    FunctionCall,
    MetaEntry,
    MetaSection,
    OptionsSection,
    RegexPattern,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.validator import YaraLValidator


def test_validator_meta_section_missing_fields_and_invalid_severity() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r_meta"

    meta = MetaSection(entries=[MetaEntry(key="severity", value="urgent")])
    validator._validate_meta_section(meta)

    messages = [warn.message for warn in validator.warnings]
    assert any("Invalid severity value: urgent" in message for message in messages)
    assert any("Missing recommended meta field: author" in message for message in messages)
    assert any("Missing recommended meta field: description" in message for message in messages)


def test_validator_meta_section_valid_and_visit_helpers() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r_meta_ok"

    meta = MetaSection(
        entries=[
            MetaEntry(key="author", value="me"),
            MetaEntry(key="description", value="desc"),
            MetaEntry(key="severity", value="high"),
        ]
    )
    validator.visit_yaral_meta_section(meta)
    validator.visit_yaral_meta_entry(meta.entries[0])
    validator.visit_yaral_regex_pattern(RegexPattern(pattern="x"))
    validator.visit_yaral_cidr_expression(
        CIDRExpression(
            field=UDMFieldAccess(event=EventVariable(name="$e"), field=UDMFieldPath(parts=["ip"])),
            cidr="10.0.0.0/8",
        )
    )
    validator.visit_yaral_function_call(FunctionCall(function="cidr", arguments=[]))

    assert validator.warnings == []
    assert validator.errors == []


@pytest.mark.parametrize(
    "arguments",
    [[], ["command_line"], ["command_line", "regex", "extra"]],
)
def test_validator_re_capture_all_requires_two_arguments(arguments: list[object]) -> None:
    validator = YaraLValidator()
    validator.visit_yaral_function_call(
        FunctionCall(function="re.capture_all", arguments=arguments)
    )

    assert len(validator.errors) == 1
    assert "expects exactly 2 arguments" in validator.errors[0].message


def test_validator_re_capture_all_rejects_numeric_arguments() -> None:
    validator = YaraLValidator()
    validator.visit_yaral_function_call(
        FunctionCall(function="re.capture_all", arguments=["command_line", 42])
    )

    assert len(validator.errors) == 1
    assert "arguments must be strings" in validator.errors[0].message


def test_validator_visits_nested_re_capture_all_calls() -> None:
    validator = YaraLValidator()
    validator.visit_yaral_function_call(
        FunctionCall(
            function="strings.concat",
            arguments=[FunctionCall(function="re.capture_all", arguments=["command_line"])],
        )
    )

    assert len(validator.errors) == 1
    assert "expects exactly 2 arguments" in validator.errors[0].message


def test_validator_options_section_unknown_and_valid_options() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r_opts"

    validator._validate_options_section(
        OptionsSection(options={"unknown_flag": True, "timeout": "5m"})
    )
    assert any("Unknown option: unknown_flag" in warn.message for warn in validator.warnings)

    validator.warnings.clear()
    validator.visit_yaral_options_section(
        OptionsSection(options={"allow_zero_values": True, "max_events": 10})
    )
    assert validator.warnings == []
