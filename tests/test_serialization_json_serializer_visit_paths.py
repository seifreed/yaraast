from __future__ import annotations

import json
from pathlib import Path

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.ast.rules import Include, Rule
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.serialization.json_serializer import JsonSerializer


def test_json_serializer_visit_methods_cover_remaining_nodes() -> None:
    s = JsonSerializer()

    assert s.visit_string_definition(StringDefinition("$s"))["type"] == "StringDefinition"
    assert s.visit_expression(Expression())["type"] == "Expression"
    assert s.visit_condition(Condition())["type"] == "Condition"

    assert s.visit_hex_token(HexByte(0x4D))["type"] == "HexToken"
    assert s.visit_hex_byte(HexByte(0x4D))["type"] == "HexByte"
    assert s.visit_hex_wildcard(HexWildcard())["type"] == "HexWildcard"
    assert s.visit_hex_jump(HexJump(1, 2))["type"] == "HexJump"
    assert (
        s.visit_hex_alternative(HexAlternative([[HexByte(1)], [HexByte(2)]]))["type"]
        == "HexAlternative"
    )
    assert s.visit_hex_nibble(HexNibble(high=True, value=0xA))["type"] == "HexNibble"

    assert s.visit_identifier(Identifier("id"))["type"] == "Identifier"
    assert s.visit_string_identifier(StringIdentifier("$a"))["type"] == "StringIdentifier"
    assert s.visit_string_wildcard(StringWildcard("$a*"))["type"] == "StringWildcard"
    assert s.visit_string_count(StringCount("a"))["type"] == "StringCount"
    assert s.visit_string_offset(StringOffset("a", IntegerLiteral(1)))["type"] == "StringOffset"
    assert s.visit_string_length(StringLength("a", IntegerLiteral(1)))["type"] == "StringLength"
    assert s.visit_integer_literal(IntegerLiteral(1))["type"] == "IntegerLiteral"
    assert s.visit_double_literal(DoubleLiteral(1.5))["type"] == "DoubleLiteral"
    assert s.visit_string_literal(StringLiteral("x"))["type"] == "StringLiteral"
    assert s.visit_regex_literal(RegexLiteral("ab.*", "i"))["type"] == "RegexLiteral"
    assert s.visit_boolean_literal(BooleanLiteral(True))["type"] == "BooleanLiteral"
    assert (
        s.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)))[
            "type"
        ]
        == "BinaryExpression"
    )
    assert (
        s.visit_unary_expression(UnaryExpression("-", IntegerLiteral(1)))["type"]
        == "UnaryExpression"
    )
    assert (
        s.visit_parentheses_expression(ParenthesesExpression(IntegerLiteral(1)))["type"]
        == "ParenthesesExpression"
    )
    assert (
        s.visit_set_expression(SetExpression([IntegerLiteral(1), IntegerLiteral(2)]))["type"]
        == "SetExpression"
    )
    assert (
        s.visit_range_expression(RangeExpression(IntegerLiteral(0), IntegerLiteral(10)))["type"]
        == "RangeExpression"
    )
    assert (
        s.visit_function_call(
            FunctionCall("math.entropy", [IntegerLiteral(0), IntegerLiteral(10)])
        )["type"]
        == "FunctionCall"
    )
    assert (
        s.visit_array_access(ArrayAccess(Identifier("arr"), IntegerLiteral(0)))["type"]
        == "ArrayAccess"
    )
    assert s.visit_member_access(MemberAccess(Identifier("pe"), "is_dll"))["type"] == "MemberAccess"

    assert (
        s.visit_for_expression(
            ForExpression(
                "any", "i", RangeExpression(IntegerLiteral(1), IntegerLiteral(2)), Identifier("i")
            ),
        )["type"]
        == "ForExpression"
    )
    assert (
        s.visit_for_of_expression(
            ForOfExpression(IntegerLiteral(1), Identifier("them"), Identifier("$a"))
        )["type"]
        == "ForOfExpression"
    )
    assert s.visit_at_expression(AtExpression("$a", IntegerLiteral(0)))["type"] == "AtExpression"
    assert (
        s.visit_in_expression(
            InExpression(
                StringIdentifier("$a"), RangeExpression(IntegerLiteral(1), IntegerLiteral(2))
            )
        )["type"]
        == "InExpression"
    )
    assert s.visit_in_expression(
        InExpression("them", RangeExpression(IntegerLiteral(1), IntegerLiteral(2)))
    ) == {
        "type": "InExpression",
        "subject": "them",
        "range": {
            "type": "RangeExpression",
            "low": {"type": "IntegerLiteral", "value": 1},
            "high": {"type": "IntegerLiteral", "value": 2},
        },
    }
    assert (
        s.visit_of_expression(OfExpression(IntegerLiteral(1), Identifier("them")))["type"]
        == "OfExpression"
    )

    assert s.visit_meta(Meta("k", "v"))["type"] == "Meta"
    assert s.visit_module_reference(ModuleReference("pe"))["type"] == "ModuleReference"
    assert (
        s.visit_dictionary_access(
            DictionaryAccess(ModuleReference("pe"), StringLiteral("CompanyName"))
        )["type"]
        == "DictionaryAccess"
    )
    assert s.visit_comment(Comment("note"))["type"] == "Comment"
    assert (
        s.visit_comment_group(CommentGroup([Comment("a"), Comment("b")]))["type"] == "CommentGroup"
    )
    assert s.visit_defined_expression(DefinedExpression(Identifier("x"))) == {
        "type": "DefinedExpression",
        "expression": {"type": "Identifier", "name": "x"},
    }
    assert s.visit_string_operator_expression(
        StringOperatorExpression(StringLiteral("a"), "icontains", StringLiteral("A"))
    ) == {
        "type": "StringOperatorExpression",
        "left": {"type": "StringLiteral", "value": "a"},
        "operator": "icontains",
        "right": {"type": "StringLiteral", "value": "A"},
    }
    assert s.visit_extern_import(ExternImport("mods.yar")) == {
        "type": "ExternImport",
        "module": None,
    }
    assert s.visit_extern_namespace(ExternNamespace("ns")) == {
        "type": "ExternNamespace",
        "name": "ns",
    }
    assert s.visit_extern_rule(ExternRule("R")) == {
        "type": "ExternRule",
        "name": "R",
    }
    assert s.visit_extern_rule_reference(ExternRuleReference("R")) == {
        "type": "ExternRuleReference",
        "name": None,
    }
    pragma = Pragma(PragmaType.PRAGMA, "pragma")
    assert s.visit_in_rule_pragma(InRulePragma(pragma)) == {
        "type": "InRulePragma",
        "pragma": pragma,
    }
    assert s.visit_pragma(pragma) == {
        "type": "Pragma",
        "directive": None,
    }
    assert s.visit_pragma_block(PragmaBlock([pragma])) == {
        "type": "PragmaBlock",
        "pragmas": [{"type": "Pragma", "directive": None}],
    }

    rule = Rule(
        name="r",
        strings=[
            PlainString("$a", value="x", modifiers=[StringModifier.from_name_value("ascii")]),
            HexString("$h", tokens=[HexByte(0x4D)]),
            RegexString("$r", regex="ab.*"),
        ],
        condition=Condition(),
    )
    rendered = s.visit_rule(rule)
    assert rendered["type"] == "Rule"


def test_json_serializer_deserialize_validates_input_and_supports_direct_ast_and_file(
    tmp_path: Path,
) -> None:
    serializer = JsonSerializer(include_metadata=False)

    with pytest.raises(ValueError, match="No JSON input provided"):
        serializer.deserialize()

    with pytest.raises(ValueError, match="Expected YaraFile, got Rule"):
        serializer.deserialize(json.dumps({"type": "Rule"}))

    direct_ast = {
        "type": "YaraFile",
        "imports": [{"type": "Import", "module": "pe", "alias": None}],
        "includes": [{"type": "Include", "path": "common.yar"}],
        "rules": [
            {
                "type": "Rule",
                "name": "r",
                "modifiers": [],
                "tags": [],
                "meta": {},
                "strings": [],
                "condition": {"type": "BooleanLiteral", "value": True},
            }
        ],
    }
    ast = serializer.deserialize(json.dumps(direct_ast))
    assert isinstance(ast, YaraFile)
    assert ast.imports[0].module == "pe"
    assert ast.includes[0].path == "common.yar"
    assert ast.rules[0].name == "r"

    path = tmp_path / "ast.json"
    path.write_text(json.dumps({"ast": direct_ast}), encoding="utf-8")
    ast_from_file = serializer.deserialize(input_path=path)
    assert ast_from_file.rules[0].name == "r"


def test_json_serializer_visit_include_and_roundtrip_without_metadata(tmp_path: Path) -> None:
    serializer = JsonSerializer(include_metadata=False)
    assert serializer.visit_include(Include("x.yar")) == {
        "type": "Include",
        "path": "x.yar",
    }

    ast = YaraFile(imports=[], includes=[], rules=[])
    rendered = serializer.serialize(ast, tmp_path / "empty.json")
    loaded = json.loads(rendered)
    assert loaded == {"ast": {"type": "YaraFile", "imports": [], "includes": [], "rules": []}}
