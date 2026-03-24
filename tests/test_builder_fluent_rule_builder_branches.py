"""Branch-focused tests for fluent rule/file builders (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.builder.fluent_file_builder import yara_file
from yaraast.builder.fluent_rule_builder import FluentRuleBuilder
from yaraast.builder.fluent_rule_presets import (
    document_rule,
    example_rules,
    malware_rule,
    network_rule,
    packed_rule,
    rule,
    trojan_rule,
)
from yaraast.errors import ValidationError


def _modifier_names(string_def: PlainString | HexString | RegexString) -> set[str]:
    return {mod.name for mod in string_def.modifiers}


def test_with_string_rejects_invalid_argument_shapes() -> None:
    builder = FluentRuleBuilder("invalid")

    with pytest.raises(ValidationError, match="Either provide"):
        builder.with_string("$only_identifier")

    with pytest.raises(ValidationError, match="Either provide"):
        builder.with_string(123)  # type: ignore[arg-type]


def test_string_context_chaining_and_and_string_path() -> None:
    built_rule = (
        FluentRuleBuilder("ctx")
        .string("$a")
        .literal("alpha")
        .ascii()
        .wide()
        .nocase()
        .fullword()
        .private()
        .xor("2A")
        .base64()
        .and_string("$mz")
        .with_mz_header_string()
        .then()
        .string("$pe")
        .pe_header()
        .then()
        .string("$email")
        .email_pattern()
        .then()
        .matches_any()
        .build()
    )

    assert [s.identifier for s in built_rule.strings] == ["$a", "$mz", "$pe", "$email"]

    first = built_rule.strings[0]
    assert isinstance(first, PlainString)
    assert first.value == "alpha"
    assert _modifier_names(first) == {
        "ascii",
        "wide",
        "nocase",
        "fullword",
        "private",
        "xor",
        "base64",
    }
    xor_mod = next(mod for mod in first.modifiers if mod.name == "xor")
    assert xor_mod.value == 0x2A

    mz = built_rule.strings[1]
    assert isinstance(mz, HexString)
    assert [tok.value for tok in mz.tokens if isinstance(tok, HexByte)] == [0x4D, 0x5A]

    pe = built_rule.strings[2]
    assert isinstance(pe, HexString)
    assert [tok.value for tok in pe.tokens if isinstance(tok, HexByte)] == [0x50, 0x45, 0x00, 0x00]

    email = built_rule.strings[3]
    assert isinstance(email, RegexString)
    assert "@" in email.regex


def test_modifier_methods_are_noop_before_any_string_is_added() -> None:
    built_rule = (
        FluentRuleBuilder("noop")
        .nocase()
        .ascii()
        .wide()
        .fullword()
        .private_string()
        .xor(5)
        .base64()
        .matches_all()
        .build()
    )

    assert built_rule.strings == []
    assert isinstance(built_rule.condition, OfExpression)


def test_convenience_factories_cover_common_builder_paths() -> None:
    basic = rule("basic").text_string("$a", "x").matches_any().build()
    assert basic.name == "basic"
    assert len(basic.strings) == 1

    malware = malware_rule("mal").build()
    assert malware.name == "mal"
    assert {t.name for t in malware.tags} == {"malware"}
    assert malware.get_meta_value("author") == "YARA AST"

    trojan = trojan_rule("troj").build()
    assert {t.name for t in trojan.tags} == {"trojan", "malware"}

    packed = packed_rule("packed").build()
    assert {t.name for t in packed.tags} == {"packed"}
    assert isinstance(packed.condition, BinaryExpression)

    document = document_rule("doc").build()
    assert {t.name for t in document.tags} == {"document"}
    assert document.get_meta_value("author") == "YARA AST"

    network = network_rule("net").build()
    assert {s.identifier for s in network.strings} == {"$ip", "$url"}
    assert isinstance(network.condition, OfExpression)


def test_file_builder_chaining_and_duplicate_elimination() -> None:
    built_file = (
        yara_file()
        .import_module("pe")
        .import_module("pe", alias="ignored")
        .include_file("common.yar")
        .include_file("common.yar")
        .rule("r1")
        .text_string("$a", "one")
        .condition("true")
        .then_rule("r2")
        .hex_string("$b", "4D 5A")
        .for_executables()
        .then_build_file()
    )

    assert len(built_file.imports) == 1
    assert built_file.imports[0].module == "pe"
    assert len(built_file.includes) == 1
    assert built_file.includes[0].path == "common.yar"
    assert [r.name for r in built_file.rules] == ["r1", "r2"]
    assert built_file.rules[1].condition is not None


def test_rule_metadata_aliases_and_example_rules_paths() -> None:
    built = (
        FluentRuleBuilder()
        .named("alias_paths")
        .private()
        .global_()
        .public()
        .with_tag("demo")
        .meta("author", "me")
        .with_meta("score", 7)
        .versioned(3)
        .regex_string("$re", "abc.*")
        .elf_header("$elf")
        .condition("true")
        .when("true")
        .with_condition("true")
        .matches_one_of("$re")
        .matches_all_of("$re")
        .build()
    )

    assert built.name == "alias_paths"
    assert "private" in {m.name for m in built.modifiers}
    assert "global" in {m.name for m in built.modifiers}
    assert built.get_meta_value("author") == "me"
    assert built.get_meta_value("version") == 3
    assert {t.name for t in built.tags} == {"demo"}
    assert {s.identifier for s in built.strings} == {"$re", "$elf"}

    examples = example_rules()
    assert [r.name for r in examples.rules] == ["example_malware", "example_packed"]
