from __future__ import annotations

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
