"""Real tests for AST diffing (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.modifiers import MetaEntry, RuleModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.pragmas import CustomPragma, DefineDirective, InRulePragma, UndefDirective
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.parser import Parser
from yaraast.serialization.ast_diff import AstDiff, AstHasher, DiffType


def _parse_yara(code: str) -> YaraFile:
    parser = Parser()
    return parser.parse(dedent(code))


def test_ast_hasher_stable_hash_and_node_hash() -> None:
    code = """
    rule alpha {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    hasher = AstHasher()

    hash1 = hasher.hash_ast(ast)
    hash2 = hasher.hash_ast(ast)

    assert hash1 == hash2
    assert len(hash1) == 16

    rule = ast.rules[0]
    node_hash = hasher.hash_node(rule, "/rules/alpha")
    assert len(node_hash) == 12
    assert hasher._node_hashes["/rules/alpha"] == node_hash


def test_ast_diff_detects_meta_scope_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="meta_scope",
                meta=[MetaEntry.from_key_value("secret", "token", "public")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="meta_scope",
                meta=[MetaEntry.from_key_value("secret", "token", "private")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.has_changes
    meta_diff = next(diff for diff in result.differences if diff.path == "/rules/meta_scope/meta")
    assert isinstance(meta_diff.old_value, dict)
    assert isinstance(meta_diff.new_value, dict)
    assert meta_diff.old_value["secret"]["scope"] == "public"
    assert meta_diff.new_value["secret"]["scope"] == "private"


def test_ast_diff_detects_meta_value_type_change() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="meta_type",
                meta=[MetaEntry.from_key_value("count", 42)],
                condition=BooleanLiteral(value=True),
            )
        ]
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="meta_type",
                meta=[MetaEntry.from_key_value("count", "42")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    hasher = AstHasher()
    assert hasher.hash_ast(old_ast) != hasher.hash_ast(new_ast)

    result = AstDiff().compare(old_ast, new_ast)

    assert result.has_changes
    meta_diff = next(diff for diff in result.differences if diff.path == "/rules/meta_type/meta")
    assert meta_diff.old_value is not None
    assert meta_diff.new_value is not None
    assert meta_diff.old_value["count"]["value"] == 42
    assert meta_diff.new_value["count"]["value"] == "42"


def test_ast_diff_detects_duplicate_meta_key_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_meta",
                meta=[
                    MetaEntry.from_key_value("author", "alice"),
                    MetaEntry.from_key_value("author", "bob"),
                ],
                condition=BooleanLiteral(value=True),
            )
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_meta",
                meta=[MetaEntry.from_key_value("author", "bob")],
                condition=BooleanLiteral(value=True),
            )
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    meta_diff = next(
        diff for diff in result.differences if diff.path == "/rules/duplicate_meta/meta"
    )
    old_value = cast(dict[str, Any], meta_diff.old_value)
    new_value = cast(dict[str, Any], meta_diff.new_value)
    assert meta_diff.diff_type == DiffType.MODIFIED
    assert isinstance(old_value["author"], list)
    assert len(old_value["author"]) == 2
    assert new_value["author"]["value"] == "bob"
    assert result.has_changes


def test_ast_diff_detects_duplicate_tag_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_tags",
                tags=[Tag("shared"), Tag("shared")],
                condition=BooleanLiteral(value=True),
            )
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_tags",
                tags=[Tag("shared")],
                condition=BooleanLiteral(value=True),
            )
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    tag_diff = next(
        diff for diff in result.differences if diff.path == "/rules/duplicate_tags/tags"
    )
    assert tag_diff.diff_type == DiffType.MODIFIED
    assert tag_diff.old_value == ["shared", "shared"]
    assert tag_diff.new_value == ["shared"]
    assert result.has_changes


def test_ast_diff_detects_duplicate_modifier_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_modifiers",
                modifiers=[
                    RuleModifier.from_string("private"),
                    RuleModifier.from_string("private"),
                ],
                condition=BooleanLiteral(value=True),
            )
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_modifiers",
                modifiers=[RuleModifier.from_string("private")],
                condition=BooleanLiteral(value=True),
            )
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    modifier_diff = next(
        diff for diff in result.differences if diff.path == "/rules/duplicate_modifiers/modifiers"
    )
    assert modifier_diff.diff_type == DiffType.MODIFIED
    assert modifier_diff.old_value == ["private", "private"]
    assert modifier_diff.new_value == ["private"]
    assert result.has_changes


def test_ast_diff_detects_duplicate_import_changes() -> None:
    old_ast = YaraFile(imports=[Import("pe"), Import("pe")])
    new_ast = YaraFile(imports=[Import("pe")])

    result = AstDiff().compare(old_ast, new_ast)

    import_diff = next(diff for diff in result.differences if diff.path == "/imports/pe")
    assert import_diff.diff_type == DiffType.MODIFIED
    assert import_diff.old_value == [{"alias": None, "module": "pe"}] * 2
    assert import_diff.new_value == [{"alias": None, "module": "pe"}]
    assert result.has_changes


def test_ast_diff_detects_duplicate_include_changes() -> None:
    old_ast = YaraFile(includes=[Include("shared.yar"), Include("shared.yar")])
    new_ast = YaraFile(includes=[Include("shared.yar")])

    result = AstDiff().compare(old_ast, new_ast)

    include_diff = next(diff for diff in result.differences if diff.path == "/includes/shared.yar")
    assert include_diff.diff_type == DiffType.MODIFIED
    assert include_diff.old_value == ["shared.yar", "shared.yar"]
    assert include_diff.new_value == ["shared.yar"]
    assert result.has_changes


def test_ast_diff_rejects_non_string_file_identity_fields() -> None:
    cases = [
        (
            "Rule name must be a string",
            YaraFile(rules=[Rule(cast(Any, False), condition=BooleanLiteral(True))]),
            YaraFile(rules=[Rule("False", condition=BooleanLiteral(True))]),
        ),
        (
            "Import module must be a string",
            YaraFile(imports=[Import(cast(Any, False))]),
            YaraFile(imports=[Import("False")]),
        ),
        (
            "Include path must be a string",
            YaraFile(includes=[Include(cast(Any, False))]),
            YaraFile(includes=[Include("False")]),
        ),
    ]

    for message, old_ast, new_ast in cases:
        with pytest.raises(TypeError, match=message):
            AstDiff().compare(old_ast, new_ast)


def test_ast_diff_detects_duplicate_string_identifier_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_strings",
                strings=[
                    PlainString("$a", value="one"),
                    PlainString("$a", value="two"),
                ],
                condition=BooleanLiteral(value=True),
            )
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_strings",
                strings=[PlainString("$a", value="two")],
                condition=BooleanLiteral(value=True),
            )
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    string_diff = next(
        diff for diff in result.differences if diff.path == "/rules/duplicate_strings/strings/$a"
    )
    assert string_diff.diff_type == DiffType.MODIFIED
    assert isinstance(string_diff.old_value, list)
    assert isinstance(string_diff.new_value, list)
    assert len(string_diff.old_value) == 2
    assert len(string_diff.new_value) == 1
    assert result.has_changes


def test_ast_diff_detects_extended_file_field_changes() -> None:
    old_ast = YaraFile(
        extern_imports=[ExternImport(module_path="external.yar", alias="ext")],
        extern_rules=[ExternRule(name="RemoteRule")],
        pragmas=[CustomPragma(name="vendor", parameters={"level": "strict"})],
        namespaces=[ExternNamespace(name="corp", extern_rules=[ExternRule(name="Nested")])],
        rules=[Rule(name="stable", condition=BooleanLiteral(value=True))],
    )
    new_ast = YaraFile(
        extern_imports=[ExternImport(module_path="external.yar", alias="renamed")],
        extern_rules=[ExternRule(name="OtherRule")],
        pragmas=[CustomPragma(name="vendor", parameters={"level": "relaxed"})],
        namespaces=[ExternNamespace(name="corp", extern_rules=[ExternRule(name="Changed")])],
        rules=[Rule(name="stable", condition=BooleanLiteral(value=True))],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    assert by_path["/extern_imports/external.yar"].diff_type == DiffType.MODIFIED
    assert by_path["/extern_rules/RemoteRule"].diff_type == DiffType.REMOVED
    assert by_path["/extern_rules/OtherRule"].diff_type == DiffType.ADDED
    assert by_path["/pragmas/custom:vendor:"].diff_type == DiffType.MODIFIED
    assert by_path["/namespaces/corp"].diff_type == DiffType.MODIFIED
    assert result.has_changes
    assert result.statistics["total_changes"] == len(result.differences)


def test_ast_diff_detects_duplicate_extended_file_field_key_changes() -> None:
    old_ast = YaraFile(
        pragmas=[
            CustomPragma("vendor", arguments=["strict"]),
            CustomPragma("vendor", arguments=["legacy"]),
        ],
    )
    new_ast = YaraFile(
        pragmas=[
            CustomPragma("vendor", arguments=["legacy"]),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    diff = by_path["/pragmas/custom:vendor:"]
    assert diff.diff_type == DiffType.MODIFIED
    assert isinstance(diff.old_value, list)
    assert isinstance(diff.new_value, list)
    assert len(diff.old_value) == 2
    assert len(diff.new_value) == 1
    assert result.has_changes


def test_ast_diff_detects_duplicate_rule_key_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(name="duplicate", condition=BooleanLiteral(value=True)),
            Rule(name="duplicate", condition=IntegerLiteral(value=1)),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(name="duplicate", condition=IntegerLiteral(value=1)),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    diff = by_path["/rules/duplicate"]
    assert diff.diff_type == DiffType.MODIFIED
    assert isinstance(diff.old_value, list)
    assert isinstance(diff.new_value, list)
    assert len(diff.old_value) == 2
    assert len(diff.new_value) == 1
    assert result.has_changes


def test_ast_diff_detects_order_sensitive_file_pragma_reordering() -> None:
    old_ast = YaraFile(
        pragmas=[
            DefineDirective("FEATURE", "1"),
            UndefDirective("FEATURE"),
        ],
    )
    new_ast = YaraFile(
        pragmas=[
            UndefDirective("FEATURE"),
            DefineDirective("FEATURE", "1"),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    assert by_path["/pragmas/order"].diff_type == DiffType.MODIFIED
    assert result.old_ast_hash != result.new_ast_hash
    assert result.has_changes


def test_ast_diff_detects_order_sensitive_in_rule_pragma_reordering() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                pragmas=[
                    InRulePragma(DefineDirective("FEATURE", "1"), position="before_condition"),
                    InRulePragma(UndefDirective("FEATURE"), position="before_condition"),
                ],
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                pragmas=[
                    InRulePragma(UndefDirective("FEATURE"), position="before_condition"),
                    InRulePragma(DefineDirective("FEATURE", "1"), position="before_condition"),
                ],
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    assert by_path["/rules/stable/pragmas/order"].diff_type == DiffType.MODIFIED
    assert result.old_ast_hash != result.new_ast_hash
    assert result.has_changes


def test_ast_diff_detects_string_offset_and_length_index_changes() -> None:
    cases = [
        (
            """
            rule offset_index {
                strings:
                    $a = "alpha"
                condition:
                    @a[1] == 1
            }
            """,
            """
            rule offset_index {
                strings:
                    $a = "alpha"
                condition:
                    @a[2] == 1
            }
            """,
            "/rules/offset_index/condition",
        ),
        (
            """
            rule length_index {
                strings:
                    $a = "alpha"
                condition:
                    !a[1] == 1
            }
            """,
            """
            rule length_index {
                strings:
                    $a = "alpha"
                condition:
                    !a[2] == 1
            }
            """,
            "/rules/length_index/condition",
        ),
    ]

    for old_code, new_code, diff_path in cases:
        result = AstDiff().compare(_parse_yara(old_code), _parse_yara(new_code))

        by_path = {diff.path: diff for diff in result.differences}
        assert by_path[diff_path].diff_type == DiffType.MODIFIED
        assert result.has_changes


def test_ast_diff_treats_string_modifier_reordering_as_unchanged() -> None:
    old_ast = _parse_yara("""
        rule modifier_order {
            strings:
                $p = "alpha" ascii xor(1-2) fullword
                $r = /alpha/ nocase wide fullword
            condition:
                $p and $r
        }
        """)
    new_ast = _parse_yara("""
        rule modifier_order {
            strings:
                $p = "alpha" fullword xor(1-2) ascii
                $r = /alpha/ fullword wide nocase
            condition:
                $p and $r
        }
        """)

    result = AstDiff().compare(old_ast, new_ast)

    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_condition_string_set_reordering_as_unchanged() -> None:
    cases = [
        (
            """
            rule of_order {
                strings:
                    $a = "alpha"
                    $b = "beta"
                condition:
                    2 of ($b, $a)
            }
            """,
            """
            rule of_order {
                strings:
                    $a = "alpha"
                    $b = "beta"
                condition:
                    2 of ($a, $b)
            }
            """,
        ),
        (
            """
            rule for_of_order {
                strings:
                    $a = "alpha"
                    $b = "beta"
                condition:
                    for any of ($b, $a) : (true)
            }
            """,
            """
            rule for_of_order {
                strings:
                    $a = "alpha"
                    $b = "beta"
                condition:
                    for any of ($a, $b) : (true)
            }
            """,
        ),
    ]

    for old_code, new_code in cases:
        result = AstDiff().compare(_parse_yara(old_code), _parse_yara(new_code))

        assert result.old_ast_hash == result.new_ast_hash
        assert not result.has_changes
        assert result.differences == []


def test_ast_diff_treats_raw_string_set_reordering_as_unchanged() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="raw_set_order",
                condition=OfExpression("any", ["$b", "$a"]),
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="raw_set_order",
                condition=OfExpression("any", ["$a", "$b"]),
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes


def test_ast_diff_treats_non_list_raw_string_sets_as_equivalent() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="raw_set_container",
                condition=OfExpression("any", ("$b", "$a")),
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="raw_set_container",
                condition=OfExpression("any", ["$a", "$b"]),
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_ast_string_set_as_equivalent_to_raw_string_set() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="ast_set_container",
                condition=OfExpression(
                    "any",
                    ParenthesesExpression(
                        SetExpression([StringLiteral("$b"), StringLiteral("$a")])
                    ),
                ),
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="ast_set_container",
                condition=OfExpression("any", ["$a", "$b"]),
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_identifier_string_set_items_as_equivalent() -> None:
    equivalent_pairs = [
        (OfExpression("any", Identifier("$a")), OfExpression("any", StringIdentifier("$a"))),
        (
            OfExpression("any", SetExpression([Identifier("$b"), Identifier("$a")])),
            OfExpression("any", ["$a", "$b"]),
        ),
    ]

    for old_condition, new_condition in equivalent_pairs:
        old_ast = YaraFile(rules=[Rule(name="identifier_set", condition=old_condition)])
        new_ast = YaraFile(rules=[Rule(name="identifier_set", condition=new_condition)])

        result = AstDiff().compare(old_ast, new_ast)

        assert result.old_ast_hash == result.new_ast_hash
        assert not result.has_changes
        assert result.differences == []


def test_ast_diff_distinguishes_rule_wildcards_from_raw_string_wildcards() -> None:
    rule_wildcard_ast = YaraFile(
        rules=[
            Rule(
                name="wildcard_set",
                condition=OfExpression("any", SetExpression([StringWildcard("helper*")])),
            ),
        ],
    )
    raw_string_wildcard_ast = YaraFile(
        rules=[
            Rule(
                name="wildcard_set",
                condition=OfExpression("any", ["helper*"]),
            ),
        ],
    )

    result = AstDiff().compare(rule_wildcard_ast, raw_string_wildcard_ast)

    assert result.old_ast_hash != result.new_ast_hash
    assert result.has_changes


def test_ast_diff_treats_bare_raw_wildcards_as_string_wildcards() -> None:
    typed_string_wildcard_ast = YaraFile(
        rules=[
            Rule(
                name="wildcard_set",
                condition=OfExpression("any", SetExpression([StringWildcard("$helper*")])),
            ),
        ],
    )
    raw_string_wildcard_ast = YaraFile(
        rules=[
            Rule(
                name="wildcard_set",
                condition=OfExpression("any", ["helper*"]),
            ),
        ],
    )

    result = AstDiff().compare(typed_string_wildcard_ast, raw_string_wildcard_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes


def test_ast_diff_ignores_dictionary_key_expression_metadata() -> None:
    old_key = IntegerLiteral(1)
    old_key.location = Location(1, 1)
    new_key = IntegerLiteral(1)
    new_key.location = Location(20, 7)
    old_ast = YaraFile(
        rules=[
            Rule(
                name="dict_key_metadata",
                condition=DictionaryAccess(ModuleReference("module"), old_key),
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="dict_key_metadata",
                condition=DictionaryAccess(ModuleReference("module"), new_key),
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_detects_hex_alternative_changes() -> None:
    old_ast = _parse_yara(
        """
        rule hex_alternative {
            strings:
                $a = { ( 4D | 5A ) }
            condition:
                $a
        }
        """,
    )
    new_ast = _parse_yara(
        """
        rule hex_alternative {
            strings:
                $a = { ( 4D | 6A ) }
            condition:
                $a
        }
        """,
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    assert by_path["/rules/hex_alternative/strings/$a"].diff_type == DiffType.MODIFIED
    assert result.has_changes


def test_ast_diff_detects_in_rule_pragma_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(
                        pragma=CustomPragma("vendor", parameters={"level": "strict"}),
                        position="before_condition",
                    ),
                ],
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(
                        pragma=CustomPragma("vendor", parameters={"level": "relaxed"}),
                        position="before_condition",
                    ),
                ],
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    assert by_path["/rules/stable/pragmas/before_condition:custom:vendor:"].diff_type == (
        DiffType.MODIFIED
    )
    assert result.has_changes


def test_ast_diff_treats_in_rule_pragma_reordering_as_unchanged() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(CustomPragma("vendor_b"), position="before_condition"),
                    InRulePragma(CustomPragma("vendor_a"), position="before_strings"),
                ],
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(CustomPragma("vendor_a"), position="before_strings"),
                    InRulePragma(CustomPragma("vendor_b"), position="before_condition"),
                ],
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_rule_string_reordering_as_unchanged() -> None:
    old_ast = _parse_yara(
        """
        rule string_order {
            strings:
                $b = "beta"
                $a = "alpha"
            condition:
                any of them
        }
        """,
    )
    new_ast = _parse_yara(
        """
        rule string_order {
            strings:
                $a = "alpha"
                $b = "beta"
            condition:
                any of them
        }
        """,
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_extended_file_field_reordering_as_unchanged() -> None:
    cases = [
        (
            YaraFile(extern_imports=[ExternImport("b.yar"), ExternImport("a.yar")]),
            YaraFile(extern_imports=[ExternImport("a.yar"), ExternImport("b.yar")]),
        ),
        (
            YaraFile(extern_rules=[ExternRule("Beta"), ExternRule("Alpha")]),
            YaraFile(extern_rules=[ExternRule("Alpha"), ExternRule("Beta")]),
        ),
        (
            YaraFile(pragmas=[CustomPragma("vendor_b"), CustomPragma("vendor_a")]),
            YaraFile(pragmas=[CustomPragma("vendor_a"), CustomPragma("vendor_b")]),
        ),
        (
            YaraFile(namespaces=[ExternNamespace("beta"), ExternNamespace("alpha")]),
            YaraFile(namespaces=[ExternNamespace("alpha"), ExternNamespace("beta")]),
        ),
    ]

    for old_ast, new_ast in cases:
        result = AstDiff().compare(old_ast, new_ast)

        assert result.old_ast_hash == result.new_ast_hash
        assert not result.has_changes
        assert result.differences == []


def test_ast_diff_treats_nested_extended_field_reordering_as_unchanged() -> None:
    cases = [
        (
            YaraFile(
                extern_imports=[
                    ExternImport("external.yar", rules=["RemoteB", "RemoteA"]),
                ],
            ),
            YaraFile(
                extern_imports=[
                    ExternImport("external.yar", rules=["RemoteA", "RemoteB"]),
                ],
            ),
        ),
        (
            YaraFile(
                namespaces=[
                    ExternNamespace(
                        "corp",
                        extern_rules=[ExternRule("Beta"), ExternRule("Alpha")],
                    ),
                ],
            ),
            YaraFile(
                namespaces=[
                    ExternNamespace(
                        "corp",
                        extern_rules=[ExternRule("Alpha"), ExternRule("Beta")],
                    ),
                ],
            ),
        ),
    ]

    for old_ast, new_ast in cases:
        result = AstDiff().compare(old_ast, new_ast)

        assert result.old_ast_hash == result.new_ast_hash
        assert not result.has_changes
        assert result.differences == []


def test_ast_diff_treats_tag_reordering_as_unchanged() -> None:
    old_ast = _parse_yara(
        """
        rule tagged : beta alpha {
            condition:
                true
        }
        """,
    )
    new_ast = _parse_yara(
        """
        rule tagged : alpha beta {
            condition:
                true
        }
        """,
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_meta_reordering_as_unchanged() -> None:
    old_ast = _parse_yara(
        """
        rule meta_order {
            meta:
                b = 2
                a = 1
            condition:
                true
        }
        """,
    )
    new_ast = _parse_yara(
        """
        rule meta_order {
            meta:
                a = 1
                b = 2
            condition:
                true
        }
        """,
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_top_level_reordering_as_unchanged() -> None:
    cases = [
        (
            """
            import "pe"
            import "elf"
            rule stable {
                condition:
                    true
            }
            """,
            """
            import "elf"
            import "pe"
            rule stable {
                condition:
                    true
            }
            """,
        ),
        (
            """
            include "b.yar"
            include "a.yar"
            rule stable {
                condition:
                    true
            }
            """,
            """
            include "a.yar"
            include "b.yar"
            rule stable {
                condition:
                    true
            }
            """,
        ),
        (
            """
            rule beta {
                condition:
                    true
            }
            rule alpha {
                condition:
                    false
            }
            """,
            """
            rule alpha {
                condition:
                    false
            }
            rule beta {
                condition:
                    true
            }
            """,
        ),
    ]

    for old_code, new_code in cases:
        result = AstDiff().compare(_parse_yara(old_code), _parse_yara(new_code))

        assert result.old_ast_hash == result.new_ast_hash
        assert not result.has_changes
        assert result.differences == []


def test_ast_diff_detects_imports_rules_and_modifications(tmp_path: Path) -> None:
    old_code = """
    import "pe"
    include "base.yar"

    rule alpha : t1 {
        meta:
            author = "a"
        strings:
            $a = "abc"
        condition:
            $a
    }

    rule beta {
        condition:
            true
    }
    """

    new_code = """
    import "pe"
    include "base.yar"

    rule alpha : t2 {
        meta:
            author = "b"
        strings:
            $a = "abcd"
            $b = /xyz/i
        condition:
            any of them
    }

    rule gamma {
        condition:
            false
    }
    """

    old_ast = _parse_yara(old_code)
    new_ast = _parse_yara(new_code)

    # Simulate import alias change without relying on parser support.
    old_ast.imports[0].alias = None
    new_ast.imports[0].alias = "pe_alias"

    differ = AstDiff()
    result = differ.compare(old_ast, new_ast)

    assert result.has_changes is True
    assert result.statistics["old_rules_count"] == 2
    assert result.statistics["new_rules_count"] == 2

    summary = result.change_summary
    assert summary[DiffType.MODIFIED.value] >= 1
    assert summary[DiffType.ADDED.value] >= 1
    assert summary[DiffType.REMOVED.value] >= 1

    import_alias_changes = [
        diff
        for diff in result.differences
        if diff.path == "/imports/pe/alias" and diff.diff_type == DiffType.MODIFIED
    ]
    assert import_alias_changes

    added_rules = [diff for diff in result.differences if diff.diff_type == DiffType.ADDED]
    removed_rules = [diff for diff in result.differences if diff.diff_type == DiffType.REMOVED]
    assert any(diff.path == "/rules/gamma" for diff in added_rules)
    assert any(diff.path == "/rules/beta" for diff in removed_rules)

    patch_path = tmp_path / "diff.json"
    patch = differ.create_patch(result, output_path=str(patch_path))
    assert patch_path.exists()
    assert patch["patch_format"] == "yaraast-diff-v1"
    assert patch["changes"]["has_changes"] is True


@pytest.mark.parametrize("output_path", [False, 0, object()])
def test_ast_diff_create_patch_rejects_invalid_output_path_types(output_path: Any) -> None:
    old = _parse_yara("rule a { condition: true }")
    new = _parse_yara("rule a { condition: false }")
    differ = AstDiff()
    result = differ.compare(old, new)

    with pytest.raises(TypeError, match="output_path must be a file path"):
        differ.create_patch(result, output_path=cast(Any, output_path))


def test_ast_diff_create_patch_rejects_empty_output_path() -> None:
    old = _parse_yara("rule a { condition: true }")
    new = _parse_yara("rule a { condition: false }")
    differ = AstDiff()
    result = differ.compare(old, new)

    with pytest.raises(ValueError, match="output_path must not be empty"):
        differ.create_patch(result, output_path="")
