"""Branch-focused tests for fluent rule/file builders (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral
from yaraast.ast.rules import Rule
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
        builder.with_string(cast(Any, 123))


def test_fluent_rule_build_does_not_accumulate_strings_between_builds() -> None:
    builder = FluentRuleBuilder("stable").text_string("$a", "alpha").matches_any()

    first = builder.build()
    second = builder.build()

    assert [string.identifier for string in first.strings] == ["$a"]
    assert [string.identifier for string in second.strings] == ["$a"]


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
        .import_module("pe")
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


def test_fluent_file_builder_rejects_duplicate_rule_names() -> None:
    first = rule("same_rule").condition("true").build()
    second = rule("same_rule").condition("false").build()
    builder = yara_file().with_rule(first)

    with pytest.raises(ValidationError, match="Duplicate rule identifier"):
        builder.with_rule(second)

    assert [built_rule.name for built_rule in builder.build().rules] == ["same_rule"]


def test_fluent_file_builder_rejects_invalid_rule_names_without_partial_update() -> None:
    builder = yara_file().with_rule(Rule(name="valid_rule"))

    with pytest.raises(ValidationError, match="Invalid rule identifier"):
        builder.with_rule(Rule(name="bad-name"))

    assert [built_rule.name for built_rule in builder.build().rules] == ["valid_rule"]


def test_fluent_file_builder_rejects_invalid_rule_inputs_without_partial_update() -> None:
    builder = yara_file().with_rule(Rule(name="valid_rule"))

    with pytest.raises(TypeError, match="Rule input must be a Rule"):
        builder.with_rule(cast(Any, object()))

    assert [built_rule.name for built_rule in builder.build().rules] == ["valid_rule"]


def test_fluent_file_builder_rejects_invalid_rule_structure_without_partial_update() -> None:
    builder = yara_file().with_rule(Rule(name="valid_rule", condition=BooleanLiteral(True)))

    with pytest.raises(TypeError, match=r"Rule\.condition must be an AST node"):
        builder.with_rule(Rule(name="bad_rule", condition=cast(Any, object())))

    assert [built_rule.name for built_rule in builder.build().rules] == ["valid_rule"]


def test_fluent_file_builder_copies_direct_rule_inputs() -> None:
    source_rule = Rule(name="stable_rule")
    builder = yara_file().with_rule(source_rule)

    source_rule.name = "bad-name"

    assert [built_rule.name for built_rule in builder.build().rules] == ["stable_rule"]


@pytest.mark.parametrize("empty_text", ["", "   ", "\t"])
def test_fluent_file_builder_rejects_empty_imports_and_includes(empty_text: str) -> None:
    builder = yara_file().import_module("pe").include_file("common.yar")

    with pytest.raises(ValidationError, match="Import module must not be empty"):
        builder.import_module(empty_text)

    with pytest.raises(ValidationError, match="Include path must not be empty"):
        builder.include_file(empty_text)

    built = builder.build()
    assert [imp.module for imp in built.imports] == ["pe"]
    assert [inc.path for inc in built.includes] == ["common.yar"]


@pytest.mark.parametrize("alias", ["p", "bad alias", "bad-alias", "for", "1bad", ""])
def test_fluent_file_builder_rejects_import_alias(alias: str) -> None:
    with pytest.raises(ValidationError, match="Import aliases are not supported"):
        yara_file().import_module("pe", alias=alias)


def test_fluent_rule_builder_rejects_duplicate_string_identifiers() -> None:
    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        rule("duplicate_strings").text_string("$a", "one").text_string(
            "a", "two"
        ).matches_any().build()


def test_fluent_rule_builder_rejects_missing_condition_builder_return() -> None:
    bad_callback = cast(Any, lambda cb: None)

    with pytest.raises(ValidationError, match="Condition builder callback must return"):
        rule("missing_condition").with_condition_builder(bad_callback)


def test_fluent_rule_builder_rejects_invalid_condition_builder_return() -> None:
    bad_callback = cast(Any, lambda cb: "bad")

    with pytest.raises(ValidationError, match="Condition builder callback must return"):
        rule("bad_condition").with_condition_builder(bad_callback)


def test_fluent_rule_builder_rejects_non_callable_condition_builder() -> None:
    with pytest.raises(TypeError, match="Condition builder callback must be callable"):
        rule("bad_condition").with_condition_builder(cast(Any, 123))


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
    assert "private" not in {m.name for m in built.modifiers}
    assert "global" in {m.name for m in built.modifiers}
    assert built.get_meta_value("author") == "me"
    assert built.get_meta_value("version") == 3
    assert {t.name for t in built.tags} == {"demo"}
    assert {s.identifier for s in built.strings} == {"$re", "$elf"}

    examples = example_rules()
    assert [r.name for r in examples.rules] == ["example_malware", "example_packed"]
