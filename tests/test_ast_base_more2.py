"""Additional tests for base AST nodes (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    RegexLiteral,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.extern import ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import IncludeOncePragma
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
)
from yaraast.optimization.expression_optimizer import ExpressionOptimizer
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    DictExpression,
    LambdaExpression,
    PatternMatch,
    WithStatement,
)


def test_ast_node_children_and_location() -> None:
    condition = BooleanLiteral(value=True)
    rule = Rule(
        name="r1",
        tags=[Tag(name="t1")],
        strings=[PlainString(identifier="$a", value="x")],
        condition=condition,
    )
    file_node = YaraFile(rules=[rule])

    children = file_node.children()
    assert rule in children
    assert condition in rule.children()

    loc = Location(line=10, column=5, file="test.yar")
    rule.location = loc
    assert rule.location.file == "test.yar"


def test_comment_group_exposes_aggregate_text() -> None:
    group = CommentGroup([Comment("one"), Comment("two")])

    assert group.text == "one\ntwo"
    group.text = "three\nfour"
    assert [comment.text for comment in group.comments] == ["three", "four"]


def test_ast_node_children_flattens_nested_ast_lists() -> None:
    byte = HexByte(value=0x11)
    wildcard = HexWildcard()
    alternative = HexAlternative(alternatives=[[byte], [wildcard]])

    assert alternative.children() == [byte, wildcard]


def test_yarafile_accept_rejects_non_ast_children() -> None:
    file_node = YaraFile(rules=[cast(Any, object())])

    with pytest.raises(TypeError, match="YaraFile rules must contain Rule nodes"):
        file_node.accept(cast(Any, object()))


def test_rule_validate_structure_rejects_non_ast_children() -> None:
    invalid_strings = Rule(name="bad", strings=[cast(Any, object())])
    with pytest.raises(TypeError, match="Rule strings must contain StringDefinition nodes"):
        invalid_strings.validate_structure()

    invalid_condition = Rule(name="bad", condition=cast(Any, object()))
    with pytest.raises(TypeError, match=r"Rule\.condition must be an AST node"):
        invalid_condition.validate_structure()


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (Import(""), "Import module cannot be empty"),
        (Import("   "), "Import module cannot be empty"),
        (Import("pe", alias=""), "Import alias cannot be empty"),
        (Include(""), "Include path cannot be empty"),
        (Include("\t"), "Include path cannot be empty"),
        (Tag(""), "Tag name cannot be empty"),
        (Tag("   "), "Tag name cannot be empty"),
        (Rule(""), "Rule name cannot be empty"),
        (Rule("   "), "Rule name cannot be empty"),
    ],
)
def test_validate_structure_rejects_empty_scalar_fields(
    node: Import | Include | Tag | Rule,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


def test_direct_yarafile_optimizers_validate_structure() -> None:
    malformed_file = YaraFile(rules=[cast(Any, object())])

    with pytest.raises(TypeError, match="YaraFile rules must contain Rule nodes"):
        ExpressionOptimizer().optimize(malformed_file)


def test_direct_yarafile_optimizers_validate_nested_hex_tokens() -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                name="bad_hex",
                strings=[HexString("$h", tokens=[cast(Any, object())])],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match=r"HexString\.tokens must contain AST nodes"):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("imports", [Import(cast(Any, object()))], "Import module must be a string"),
        ("includes", [Include(cast(Any, object()))], "Include path must be a string"),
        ("rules", [Rule(cast(Any, object()))], "Rule name must be a string"),
        ("rules", [Rule("bad_tag", tags=[Tag(cast(Any, object()))])], "Tag name must be a string"),
        (
            "rules",
            [Rule("bad_string", strings=[PlainString(cast(Any, object()), "x")])],
            "String identifier must be a string",
        ),
        (
            "rules",
            [Rule("bad_value", strings=[PlainString("$a", value=cast(Any, object()))])],
            "Plain string value must be a string or bytes",
        ),
    ],
)
def test_direct_yarafile_optimizers_validate_scalar_fields(
    field_name: str,
    value: Any,
    message: str,
) -> None:
    malformed_file = YaraFile()
    setattr(malformed_file, field_name, value)

    with pytest.raises(TypeError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            WithStatement(cast(Any, object()), BooleanLiteral(True)),
            "WithStatement declarations must be a list or tuple",
        ),
        (
            WithStatement([cast(Any, object())], BooleanLiteral(True)),
            "WithStatement declarations must contain WithDeclaration nodes",
        ),
        (
            DictExpression([cast(Any, object())]),
            "DictExpression items must contain DictItem nodes",
        ),
        (
            PatternMatch(BooleanLiteral(True), [cast(Any, object())]),
            "PatternMatch cases must contain MatchCase nodes",
        ),
        (
            LambdaExpression([cast(Any, object())], BooleanLiteral(True)),
            "Local variable name must be a string",
        ),
    ],
)
def test_direct_yarafile_analysis_validates_yarax_condition_structure(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_yarax", condition=condition)])

    with pytest.raises(TypeError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (Identifier(""), "Identifier name cannot be empty"),
        (StringIdentifier(""), "String identifier cannot be empty"),
        (StringWildcard(""), "String wildcard pattern cannot be empty"),
        (StringCount(""), "String count identifier cannot be empty"),
        (StringOffset(""), "String offset identifier cannot be empty"),
        (StringLength(""), "String length identifier cannot be empty"),
        (FunctionCall("", []), "Function name cannot be empty"),
        (
            FunctionCall("fn", [cast(Any, object())]),
            "Function arguments must contain AST nodes",
        ),
        (
            MemberAccess(Identifier("obj"), ""),
            "MemberAccess member cannot be empty",
        ),
        (ModuleReference(""), "ModuleReference module cannot be empty"),
        (
            DictionaryAccess(ModuleReference("pe"), ""),
            "DictionaryAccess key cannot be empty",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_empty_expression_scalars(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_expression", condition=condition)])

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (BooleanLiteral(cast(Any, 1)), "Boolean literal value must be a boolean"),
        (IntegerLiteral(cast(Any, True)), "Integer literal value must be an integer"),
        (IntegerLiteral(cast(Any, "1")), "Integer literal value must be an integer"),
        (DoubleLiteral(cast(Any, True)), "Double literal value must be numeric"),
        (DoubleLiteral(cast(Any, "1.0")), "Double literal value must be numeric"),
        (DoubleLiteral(float("nan")), "Double literal value must be finite"),
        (DoubleLiteral(float("inf")), "Double literal value must be finite"),
        (StringLiteral(cast(Any, object())), "String literal value must be a string"),
        (RegexLiteral(cast(Any, object())), "Regex literal pattern must be a string"),
        (RegexLiteral(""), "RegexLiteral pattern must not be empty"),
        (RegexLiteral("x", cast(Any, object())), "Regex literal modifiers must be a string"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_literal_scalars(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_literal", condition=condition)])

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (AtExpression("", IntegerLiteral(0)), "AtExpression string_id must not be empty"),
        (
            AtExpression(cast(Any, 7), IntegerLiteral(0)),
            "AtExpression string_id must be a string or expression",
        ),
        (AtExpression("$a", cast(Any, object())), "'at' offset must be an AST node"),
        (InExpression("", Identifier("filesize")), "InExpression subject must not be empty"),
        (
            InExpression(cast(Any, 7), Identifier("filesize")),
            "InExpression subject must be a string or expression",
        ),
        (InExpression("$a", cast(Any, object())), "'in' range must be an AST node"),
        (
            ForExpression(cast(Any, ["any"]), "i", Identifier("items"), BooleanLiteral(True)),
            "ForExpression quantifier must be a string, number, or expression",
        ),
        (
            ForExpression(float("nan"), "i", Identifier("items"), BooleanLiteral(True)),
            "ForExpression quantifier must be finite",
        ),
        (
            ForExpression("any", "", Identifier("items"), BooleanLiteral(True)),
            "ForExpression variable must not be empty",
        ),
        (
            ForExpression("any", cast(Any, ["i"]), Identifier("items"), BooleanLiteral(True)),
            "ForExpression variable must be a string",
        ),
        (
            ForExpression("any", "i", cast(Any, object()), BooleanLiteral(True)),
            "ForExpression iterable must be an AST expression",
        ),
        (
            ForExpression("any", "i", Identifier("items"), cast(Any, object())),
            "ForExpression body must be an AST expression",
        ),
        (
            ForOfExpression("any", cast(Any, object()), BooleanLiteral(True)),
            "ForOfExpression string_set must be",
        ),
        (
            ForOfExpression("any", [cast(Any, object())], BooleanLiteral(True)),
            "ForOfExpression string_set must contain strings or expressions",
        ),
        (
            ForOfExpression(float("inf"), ["$a"], BooleanLiteral(True)),
            "ForOfExpression quantifier must be finite",
        ),
        (
            ForOfExpression("any", ["$a"], cast(Any, object())),
            "ForOfExpression condition must be an AST expression",
        ),
        (
            OfExpression(cast(Any, True), ["$a"]),
            "OfExpression quantifier must be a string, number, or expression",
        ),
        (OfExpression("any", cast(Any, {})), "OfExpression string_set is required"),
        (
            DefinedExpression(cast(Any, object())),
            "DefinedExpression expression must be an AST expression",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), "", StringLiteral("b")),
            "StringOperatorExpression operator must not be empty",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), cast(Any, object()), StringLiteral("b")),
            "StringOperatorExpression operator must be a string",
        ),
        (
            StringOperatorExpression(cast(Any, object()), "contains", StringLiteral("b")),
            "StringOperatorExpression left must be an AST expression",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), "contains", cast(Any, object())),
            "StringOperatorExpression right must be an AST expression",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_condition_scalars(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_condition", condition=condition)])

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("token", "message"),
    [
        (HexByte(cast(Any, object())), "HexByte value must be a byte"),
        (HexByte(-1), "HexByte value must be a byte"),
        (HexByte(0x100), "HexByte value must be a byte"),
        (
            HexNegatedByte(cast(Any, object())),
            "HexNegatedByte value must be a byte",
        ),
        (
            HexJump(cast(Any, object()), 2),
            "HexJump min_jump must be a non-negative integer",
        ),
        (HexJump(4, 2), "HexJump min_jump cannot exceed max_jump"),
        (
            HexAlternative(cast(Any, object())),
            "HexAlternative must contain at least one branch",
        ),
        (
            HexAlternative([[HexByte(1)], [cast(Any, object())]]),
            "Unsupported hex token 'object'",
        ),
        (HexNibble(cast(Any, "yes"), 1), "HexNibble high must be a boolean"),
        (HexNibble(True, cast(Any, object())), "HexNibble value must be a nibble"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_hex_token_scalars(
    token: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                "bad_hex_token",
                strings=[HexString("$a", tokens=[token])],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("meta", "message"),
    [
        ([Meta("", "x")], "Meta key cannot be empty"),
        ([Meta(cast(Any, 123), "x")], "Meta key must be a string"),
        ([Meta("x", cast(Any, object()))], "Meta value must be a string"),
        ([MetaEntry("", "x")], "Meta key cannot be empty"),
        ([MetaEntry(cast(Any, 123), "x")], "Meta key must be a string"),
        ([MetaEntry("x", cast(Any, object()))], "Meta value must be a string"),
        ([MetaEntry("x", float("nan"))], "Meta value must be a string"),
        ([cast(Any, object())], "Rule meta must contain Meta or MetaEntry nodes"),
        (cast(Any, False), "Rule meta must contain Meta or MetaEntry nodes"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_rule_meta_fields(
    meta: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_meta", meta=meta, condition=BooleanLiteral(True))])

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


def test_direct_yarafile_analysis_rejects_mutated_scalar_rule_meta() -> None:
    rule = Rule("bad_meta", condition=BooleanLiteral(True))
    rule.meta = cast(Any, False)
    malformed_file = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match="Rule meta must be a list or tuple"):
        ExpressionOptimizer().optimize(malformed_file)


def test_direct_yarafile_analysis_rejects_invalid_meta_entry_scope() -> None:
    meta = MetaEntry("key", "value")
    cast(Any, meta).scope = "secret"
    malformed_file = YaraFile(
        rules=[Rule("bad_meta_scope", meta=[meta], condition=BooleanLiteral(True))]
    )

    with pytest.raises(TypeError, match="Meta scope must be a MetaScope"):
        ExpressionOptimizer().optimize(malformed_file)


def test_yarafile_helpers() -> None:
    file_node = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[Rule(name="r1")],
    )
    assert file_node.get_all_rules()[0].name == "r1"

    pragma = IncludeOncePragma()
    file_node.add_pragma(pragma)
    assert file_node.has_include_once() is True

    extern_rule = ExternRule(name="ext1", namespace="ext")
    file_node.add_extern_rule(extern_rule)
    assert file_node.get_extern_rule_by_name("ext1", "ext") == extern_rule


def test_parser_populates_location_spans_for_core_nodes() -> None:
    ast = Parser().parse("""
rule sample {
    strings:
        $a = "abc"
    condition:
        $a or true
}
""".lstrip())

    rule = ast.rules[0]
    string_def = rule.strings[0]

    assert rule.location is not None
    assert rule.location.end_line is not None
    assert rule.location.end_column is not None
    assert string_def.location is not None
    assert string_def.location.end_line is not None
    assert string_def.location.end_column is not None
    assert rule.condition is not None
    assert rule.condition.location is not None
    assert rule.condition.location.end_line is not None
