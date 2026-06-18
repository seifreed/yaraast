"""Additional tests for base AST nodes (no mocks)."""

from __future__ import annotations

import re
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
    ArrayAccess,
    BooleanLiteral,
    DoubleLiteral,
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
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, StringModifier, StringModifierType
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    IncludeOncePragma,
    InRulePragma,
    Pragma,
    PragmaType,
    UndefDirective,
)
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
    RegexString,
)
from yaraast.optimization.expression_optimizer import ExpressionOptimizer
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    LambdaExpression,
    PatternMatch,
    TupleExpression,
    WithDeclaration,
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


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (WithDeclaration("", IntegerLiteral(1)), "WithDeclaration identifier must not be empty"),
        (
            ArrayComprehension(Identifier("x"), " ", Identifier("xs")),
            "ArrayComprehension variable must not be empty",
        ),
        (
            DictComprehension(Identifier("k"), Identifier("v"), "", None, Identifier("xs")),
            "DictComprehension key_variable must not be empty",
        ),
        (
            DictComprehension(Identifier("k"), Identifier("v"), "k", " ", Identifier("xs")),
            "DictComprehension value_variable must not be empty",
        ),
        (
            LambdaExpression(parameters=[""], body=BooleanLiteral(True)),
            "LambdaExpression parameters item must not be empty",
        ),
    ],
)
def test_yarax_validate_structure_rejects_empty_local_identifiers(
    node: WithDeclaration | ArrayComprehension | DictComprehension | LambdaExpression,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


@pytest.mark.parametrize(
    ("node", "identifier"),
    [
        (WithDeclaration("bad-name", IntegerLiteral(1)), "bad-name"),
        (WithDeclaration("$bad-name", IntegerLiteral(1)), "$bad-name"),
        (ArrayComprehension(Identifier("x"), "1bad", Identifier("xs")), "1bad"),
        (
            DictComprehension(Identifier("k"), Identifier("v"), "for", None, Identifier("xs")),
            "for",
        ),
        (
            DictComprehension(Identifier("k"), Identifier("v"), "k", "bad-name", Identifier("xs")),
            "bad-name",
        ),
        (LambdaExpression(parameters=["1bad"], body=BooleanLiteral(True)), "1bad"),
    ],
)
def test_yarax_validate_structure_rejects_invalid_local_identifiers(
    node: WithDeclaration | ArrayComprehension | DictComprehension | LambdaExpression,
    identifier: str,
) -> None:
    with pytest.raises(
        ValueError,
        match=re.escape(f"Invalid local variable identifier: {identifier}"),
    ):
        node.validate_structure()


def test_yarax_validate_structure_allows_with_string_reference_identifier() -> None:
    WithDeclaration("$x", IntegerLiteral(1)).validate_structure()


@pytest.mark.parametrize("variable", ["bad-name", "1bad", "for", "i, "])
def test_for_expression_validate_structure_rejects_invalid_loop_variables(
    variable: str,
) -> None:
    condition = ForExpression(
        "any",
        variable,
        SetExpression([IntegerLiteral(1)]),
        BooleanLiteral(True),
    )

    with pytest.raises(ValueError, match=r"[Ll]ocal variable"):
        condition.validate_structure()


@pytest.mark.parametrize("variable", ["as", "include", "i, j"])
def test_for_expression_validate_structure_allows_valid_loop_variables(
    variable: str,
) -> None:
    ForExpression(
        "any",
        variable,
        SetExpression([IntegerLiteral(1)]),
        BooleanLiteral(True),
    ).validate_structure()


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
        (Identifier("bad-name"), "Invalid identifier"),
        (Identifier("$bad-name"), "Invalid string reference"),
        (StringIdentifier("$bad-name"), "Invalid string reference"),
        (StringWildcard("$bad-name*"), "Invalid string reference"),
        (StringCount("#a"), "Invalid string reference"),
        (StringCount("$bad-name"), "Invalid string reference"),
        (StringOffset("@a"), "Invalid string reference"),
        (StringOffset("$bad-name"), "Invalid string reference"),
        (StringLength("!a"), "Invalid string reference"),
        (StringLength("$bad-name"), "Invalid string reference"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_expression_identifiers(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_expression", condition=condition)])

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    "condition",
    [
        AtExpression("@a", IntegerLiteral(0)),
        AtExpression("$bad-name", IntegerLiteral(0)),
        InExpression("@a", Identifier("filesize")),
        InExpression("$bad-name", Identifier("filesize")),
        OfExpression("any", "$bad-name"),
        OfExpression("any", ["$a", "$bad-name"]),
        ForOfExpression("any", "$bad-name", BooleanLiteral(True)),
        ForOfExpression("any", ["$a", "$bad-name"], BooleanLiteral(True)),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_raw_condition_string_references(
    condition: Any,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_condition_reference", condition=condition)])

    with pytest.raises(ValueError, match="Invalid string reference"):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (OfExpression("any", [Identifier("helper"), "$a"]), "Mixed string and rule set"),
        (
            OfExpression("any", SetExpression([Identifier("helper"), Identifier("$a")])),
            "Mixed string and rule set",
        ),
        (OfExpression("any", [StringWildcard("helper*"), "$a"]), "Mixed string and rule set"),
        (
            ForOfExpression("any", [Identifier("helper"), "$a"], None),
            "Mixed string and rule set",
        ),
        (
            ForOfExpression(
                "any",
                SetExpression([StringWildcard("helper*"), Identifier("$a")]),
                BooleanLiteral(True),
            ),
            "Mixed string and rule set",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_rule_set_condition_combinations(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                "bad_rule_set_condition",
                strings=[PlainString("$a", "needle")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(ValueError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            AtExpression(OfExpression("any", Identifier("helper")), IntegerLiteral(0)),
            "Rule sets cannot use at/in restrictions",
        ),
        (
            InExpression(
                OfExpression("any", StringWildcard("helper*")),
                RangeExpression(IntegerLiteral(0), IntegerLiteral(1)),
            ),
            "Rule sets cannot use at/in restrictions",
        ),
        (
            AtExpression(OfExpression(DoubleLiteral(0.5), Identifier("them")), IntegerLiteral(0)),
            "Percentage of-expressions do not support at/in restrictions",
        ),
        (
            InExpression(
                OfExpression(StringLiteral("50%"), Identifier("them")),
                RangeExpression(IntegerLiteral(0), IntegerLiteral(1)),
            ),
            "Percentage of-expressions do not support at/in restrictions",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_restricted_of_expressions(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                "bad_restricted_of",
                strings=[PlainString("$a", "needle")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(ValueError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (
            MemberAccess(AtExpression(IntegerLiteral(1), IntegerLiteral(2)), "x"),
            "MemberAccess.object must not be an 'at' or 'with' expression",
        ),
        (
            MemberAccess(
                ParenthesesExpression(AtExpression(IntegerLiteral(1), IntegerLiteral(2))),
                "x",
            ),
            "MemberAccess.object must not be an 'at' or 'with' expression",
        ),
        (
            MemberAccess(
                WithStatement([WithDeclaration("a", IntegerLiteral(1))], Identifier("a")),
                "x",
            ),
            "MemberAccess.object must not be an 'at' or 'with' expression",
        ),
        (
            ArrayAccess(TupleExpression([IntegerLiteral(1), IntegerLiteral(2)]), IntegerLiteral(0)),
            "ArrayAccess.array must not be a tuple expression",
        ),
        (
            ArrayAccess(ModuleReference("pe"), IntegerLiteral(0)),
            "ArrayAccess.array must not be a module reference",
        ),
        (
            ArrayAccess(ParenthesesExpression(ModuleReference("pe")), IntegerLiteral(0)),
            "ArrayAccess.array must not be a module reference",
        ),
        (
            ArrayAccess(
                ParenthesesExpression(TupleExpression([IntegerLiteral(1), IntegerLiteral(2)])),
                IntegerLiteral(0),
            ),
            "ArrayAccess.array must not be a tuple expression",
        ),
        (
            ModuleReference("bad-name"),
            "Invalid module identifier",
        ),
        (
            FunctionCall("map", [], receiver=AtExpression(IntegerLiteral(1), IntegerLiteral(2))),
            "FunctionCall.receiver must not be an 'at' or 'with' expression",
        ),
        (
            FunctionCall(
                "map",
                [],
                receiver=WithStatement([WithDeclaration("a", IntegerLiteral(1))], Identifier("a")),
            ),
            "FunctionCall.receiver must not be an 'at' or 'with' expression",
        ),
    ],
)
def test_expression_validation_rejects_invalid_postfix_receivers(
    node: Any,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (ExternNamespace("bad-name"), "Invalid namespace identifier"),
        (ExternRule("bad-name"), "Invalid extern rule identifier"),
        (ExternRule("Remote", namespace="bad-name"), "Invalid namespace identifier"),
        (ExternRuleReference("bad-rule"), "Invalid extern rule identifier"),
        (
            ExternRuleReference("Remote", namespace="bad-name"),
            "Invalid namespace identifier",
        ),
        (
            ExternImport("mods.yar", rules=["bad-rule"]),
            "Invalid extern rule identifier",
        ),
        (
            ExternImport("mods.yar", alias="bad-name"),
            "Invalid import alias identifier",
        ),
        (
            ExternImport("mods.yar", alias="for"),
            "Invalid import alias identifier",
        ),
    ],
)
def test_extern_validation_rejects_invalid_identifiers(node: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


@pytest.mark.parametrize("alias", ["bad-name", "for"])
def test_import_validate_structure_rejects_invalid_alias(alias: str) -> None:
    with pytest.raises(ValueError, match="Invalid import alias identifier"):
        Import("pe", alias=alias).validate_structure()


@pytest.mark.parametrize(
    ("malformed_file", "message"),
    [
        (
            YaraFile(imports=[Import('bad"module')], rules=[Rule("bad_import")]),
            "Import module must not contain quotes or control characters",
        ),
        (
            YaraFile(imports=[Import("bad\nmodule")], rules=[Rule("bad_import")]),
            "Import module must not contain quotes or control characters",
        ),
        (
            YaraFile(includes=[Include('bad"path')], rules=[Rule("bad_include")]),
            "Include path must not contain quotes or control characters",
        ),
        (
            YaraFile(includes=[Include("bad\x00path")], rules=[Rule("bad_include")]),
            "Include path must not contain quotes or control characters",
        ),
        (
            YaraFile(
                extern_imports=[ExternImport('bad"module')],
                rules=[Rule("bad_extern_import")],
            ),
            "ExternImport module_path must not contain quotes or control characters",
        ),
        (
            YaraFile(
                extern_imports=[ExternImport("bad\x7fmodule")],
                rules=[Rule("bad_extern_import")],
            ),
            "ExternImport module_path must not contain quotes or control characters",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_quoted_fields(
    malformed_file: YaraFile,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (Rule("bad-name"), "Invalid rule identifier"),
        (Tag("bad-name"), "Invalid tag identifier"),
        (Meta("bad-name", "value"), "Invalid meta identifier"),
    ],
)
def test_rule_metadata_validate_structure_rejects_invalid_identifiers(
    node: Any,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


@pytest.mark.parametrize("key", ["as", "include"])
def test_meta_entry_validate_structure_allows_contextual_keywords(key: str) -> None:
    MetaEntry(key, "value").validate_structure()


def test_rule_validate_structure_rejects_keyword_names() -> None:
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        Rule("strings").validate_structure()


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (Pragma(PragmaType.PRAGMA, "bad-name"), "Invalid pragma identifier"),
        (CustomPragma("bad-name"), "Invalid pragma identifier"),
        (DefineDirective("bad-name"), "Invalid pragma macro identifier"),
        (UndefDirective("bad-name"), "Invalid pragma macro identifier"),
        (
            ConditionalDirective(PragmaType.IFDEF, "bad-name"),
            "Invalid pragma condition identifier",
        ),
    ],
)
def test_pragma_validate_structure_rejects_invalid_identifiers(
    node: Any,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


def test_in_rule_pragma_validate_structure_rejects_invalid_position() -> None:
    with pytest.raises(ValueError, match="Invalid InRulePragma position"):
        InRulePragma(CustomPragma("vendor"), "sideways").validate_structure()


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (Pragma(PragmaType.PRAGMA, "vendor", arguments=[""]), "Pragma argument must not be empty"),
        (CustomPragma("vendor", arguments=[""]), "Pragma argument must not be empty"),
        (DefineDirective("FLAG", ""), "Pragma value must not be empty"),
    ],
)
def test_pragma_validate_structure_rejects_empty_values(node: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


def test_string_definition_validate_structure_rejects_invalid_identifier() -> None:
    with pytest.raises(ValueError, match="Invalid string identifier"):
        PlainString("$bad-name", value="needle").validate_structure()


def test_string_definition_validate_structure_allows_anonymous_placeholder() -> None:
    PlainString("$", value="needle", is_anonymous=True).validate_structure()


@pytest.mark.parametrize(
    ("string_def", "message"),
    [
        (RegexString("$r", "line\nbreak"), "Regex pattern must not contain line breaks"),
        (RegexString("$r", "nul\x00byte"), "Regex pattern must not contain NUL bytes"),
        (
            RegexString("$r", "bad\ud800surrogate"),
            "Regex pattern must not contain Unicode surrogate code points",
        ),
        (RegexString("$r", "bad["), "Invalid regex pattern"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_regex_string_patterns(
    string_def: RegexString,
    message: str,
) -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                "bad_regex_string",
                strings=[string_def],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(ValueError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (RegexLiteral("line\nbreak"), "Regex pattern must not contain line breaks"),
        (RegexLiteral("nul\x00byte"), "Regex pattern must not contain NUL bytes"),
        (
            RegexLiteral("bad\ud800surrogate"),
            "Regex pattern must not contain Unicode surrogate code points",
        ),
        (RegexLiteral("bad["), "Invalid regex pattern"),
        (RegexLiteral("abc", "ii"), "Duplicate regex modifier"),
        (RegexLiteral("abc", "si"), "Invalid regex modifier order"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_regex_literals(
    condition: RegexLiteral,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_regex_literal", condition=condition)])

    with pytest.raises(ValueError, match=message):
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
            ForExpression("50%", "i", Identifier("items"), BooleanLiteral(True)),
            "Invalid ForExpression quantifier",
        ),
        (
            ForExpression("-1", "i", Identifier("items"), BooleanLiteral(True)),
            "Invalid ForExpression quantifier",
        ),
        (
            ForExpression(0.5, "i", Identifier("items"), BooleanLiteral(True)),
            "Invalid ForExpression quantifier",
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
            ForOfExpression("0%", ["$a"], None),
            "Invalid ForOfExpression quantifier",
        ),
        (
            ForOfExpression("101%", ["$a"], None),
            "Invalid ForOfExpression quantifier",
        ),
        (
            ForOfExpression("50%", ["$a"], BooleanLiteral(True)),
            "Invalid ForOfExpression quantifier",
        ),
        (
            ForOfExpression("any", ["$a"], cast(Any, object())),
            "ForOfExpression condition must be an AST expression",
        ),
        (
            OfExpression(cast(Any, True), ["$a"]),
            "OfExpression quantifier must be a string, number, or expression",
        ),
        (OfExpression("0%", ["$a"]), "Invalid OfExpression quantifier"),
        (OfExpression("101%", ["$a"]), "Invalid OfExpression quantifier"),
        (OfExpression(0.0, ["$a"]), "Invalid OfExpression quantifier"),
        (OfExpression(1.01, ["$a"]), "Invalid OfExpression quantifier"),
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
    ("subject", "error_type", "message"),
    [
        (
            cast(Any, object()),
            TypeError,
            "InExpression subject must be a string or expression",
        ),
        ("", ValueError, "InExpression subject must not be empty"),
        ("   ", ValueError, "InExpression subject must not be empty"),
        (Identifier(""), ValueError, "Identifier name cannot be empty"),
    ],
)
def test_in_expression_string_id_property_rejects_invalid_subject_state(
    subject: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    condition = InExpression(subject, Identifier("filesize"))

    with pytest.raises(error_type, match=message):
        _ = condition.string_id


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
        ([MetaEntry("bad-name", "x")], "Invalid meta identifier"),
        ([MetaEntry("for", "x")], "Invalid meta identifier"),
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


@pytest.mark.parametrize(
    ("modifiers", "message"),
    [
        (cast(Any, False), "Rule modifiers must be a list"),
        ([cast(Any, object())], "Rule modifiers item must be RuleModifier or string"),
        ([""], "Rule modifier name cannot be empty"),
        (["bad"], "Invalid rule modifier"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_rule_modifiers(
    modifiers: Any,
    message: str,
) -> None:
    rule = Rule("bad_rule_modifier", condition=BooleanLiteral(True))
    rule.modifiers = modifiers
    malformed_file = YaraFile(rules=[rule])

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


@pytest.mark.parametrize(
    ("pragma", "message"),
    [
        (
            Pragma(cast(Any, "bad"), "name"),
            "Pragma type must be a PragmaType",
        ),
        (Pragma(PragmaType.CUSTOM, ""), "Pragma name cannot be empty"),
        (
            Pragma(PragmaType.CUSTOM, "vendor", arguments=cast(Any, "arg")),
            "Pragma arguments must be a list of strings",
        ),
        (
            Pragma(PragmaType.CUSTOM, "vendor", arguments=[cast(Any, 1)]),
            "Pragma arguments must be a list of strings",
        ),
        (
            Pragma(PragmaType.CUSTOM, "vendor", scope=cast(Any, "file")),
            "Pragma scope must be a PragmaScope",
        ),
        (CustomPragma("", arguments=["x"]), "Pragma name cannot be empty"),
        (
            CustomPragma("vendor", parameters=cast(Any, [("key", "value")])),
            "Pragma parameters must be a dictionary",
        ),
        (
            CustomPragma("vendor", parameters={cast(Any, 1): "value"}),
            "Pragma parameters keys must be strings",
        ),
        (
            CustomPragma("vendor", parameters={"config": cast(Any, object())}),
            "Pragma parameter value must be a string",
        ),
        (
            CustomPragma("vendor", parameters={"score": float("nan")}),
            "Pragma parameter value must be a string",
        ),
        (DefineDirective(""), "Pragma macro_name cannot be empty"),
        (UndefDirective(""), "Pragma argument must not be empty"),
        (ConditionalDirective(PragmaType.IFDEF, ""), "Pragma condition cannot be empty"),
        (ConditionalDirective(PragmaType.IFDEF), "Pragma condition must be a string"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_pragma_fields(
    pragma: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(pragmas=[pragma])

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("in_rule_pragma", "message"),
    [
        (
            InRulePragma(cast(Any, object())),
            "InRulePragma pragma must be a Pragma",
        ),
        (
            InRulePragma(Pragma(PragmaType.CUSTOM, "vendor"), ""),
            "InRulePragma position cannot be empty",
        ),
        (
            InRulePragma(Pragma(PragmaType.CUSTOM, "vendor"), cast(Any, 123)),
            "InRulePragma position must be a string",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_in_rule_pragmas(
    in_rule_pragma: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                "bad_in_rule_pragma",
                pragmas=[in_rule_pragma],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


def test_direct_yarafile_analysis_rejects_invalid_pragma_block_fields() -> None:
    from yaraast.ast.pragmas import PragmaBlock

    block = PragmaBlock([Pragma(PragmaType.CUSTOM, "vendor")], scope=cast(Any, "file"))

    with pytest.raises(TypeError, match="Pragma scope must be a PragmaScope"):
        block.validate_structure()


@pytest.mark.parametrize(
    ("comment", "message"),
    [
        (Comment(cast(Any, 123)), "Comment text must be a string"),
        (
            Comment("note", is_multiline=cast(Any, "false")),
            "Comment is_multiline must be a boolean",
        ),
        (
            CommentGroup([Comment("ok"), cast(Any, object())]),
            "CommentGroup comments must contain Comment nodes",
        ),
        (
            CommentGroup(cast(Any, "bad")),
            "CommentGroup comments must be a list",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_comment_metadata(
    comment: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_comment", condition=BooleanLiteral(True))])
    malformed_file.leading_comments = [comment]

    with pytest.raises(TypeError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("comment", "message"),
    [
        (Comment("line\nbreak"), "Comment text must not contain newlines"),
        (Comment("line\rbreak"), "Comment text must not contain newlines"),
        (Comment("bad\x00nul"), "Comment text must not contain embedded NUL"),
        (
            Comment("bad\ud800surrogate"),
            "Comment text must not contain Unicode surrogate code points",
        ),
        (
            Comment("/* a */ b */"),
            "Block comment text must not contain embedded terminators",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_comment_text(
    comment: Comment,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_comment", condition=BooleanLiteral(True))])
    malformed_file.leading_comments = [comment]

    with pytest.raises(ValueError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("group", "message"),
    [
        (
            CommentGroup(cast(Any, "bad")),
            "CommentGroup comments must be a list",
        ),
        (
            CommentGroup(cast(Any, ["bad"])),
            "CommentGroup comments must contain Comment nodes",
        ),
        (
            CommentGroup([Comment(cast(Any, 123))]),
            "Comment text must be a string",
        ),
    ],
)
def test_comment_group_text_rejects_invalid_comment_state(
    group: CommentGroup,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        _ = group.text


def test_direct_yarafile_analysis_rejects_invalid_child_node_comment_metadata() -> None:
    rule = Rule("bad_child_comment", condition=BooleanLiteral(True))
    rule.leading_comments = [cast(Any, object())]
    malformed_file = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match="leading_comments must contain Comment"):
        ExpressionOptimizer().optimize(malformed_file)


def test_direct_yarafile_analysis_rejects_invalid_trailing_comment_metadata() -> None:
    rule = Rule("bad_trailing_comment", condition=BooleanLiteral(True))
    rule.trailing_comment = cast(Any, object())
    malformed_file = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match="trailing_comment must be a Comment"):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("location", "message"),
    [
        (cast(Any, object()), "location must be a Location"),
        (Location(cast(Any, True), 1), "Location line must be an integer"),
        (Location(cast(Any, "1"), 1), "Location line must be an integer"),
        (Location(1, cast(Any, False)), "Location column must be an integer"),
        (Location(1, cast(Any, "1")), "Location column must be an integer"),
        (Location(1, 1, file=cast(Any, 123)), "Location file must be a string"),
        (Location(1, 1, end_line=cast(Any, False)), "Location end_line must be an integer"),
        (Location(1, 1, end_column=cast(Any, "1")), "Location end_column must be an integer"),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_location_metadata(
    location: Any,
    message: str,
) -> None:
    rule = Rule("bad_location", condition=BooleanLiteral(True))
    rule.location = location
    malformed_file = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("location", "message"),
    [
        (Location(0, 1), "Location line must be at least 1"),
        (Location(-1, 1), "Location line must be at least 1"),
        (Location(1, 0), "Location column must be at least 1"),
        (Location(1, -1), "Location column must be at least 1"),
        (Location(1, 1, end_line=0), "Location end_line must be at least 1"),
        (Location(1, 1, end_column=0), "Location end_column must be at least 1"),
    ],
)
def test_direct_yarafile_analysis_rejects_non_positive_location_metadata(
    location: Location,
    message: str,
) -> None:
    rule = Rule("bad_location", condition=BooleanLiteral(True))
    rule.location = location
    malformed_file = YaraFile(rules=[rule])

    with pytest.raises(ValueError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("malformed_file", "message"),
    [
        (
            YaraFile(extern_rules=[ExternRule(cast(Any, 123))]),
            "ExternRule name must be a string",
        ),
        (
            YaraFile(extern_rules=[ExternRule("")]),
            "ExternRule name cannot be empty",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", modifiers=cast(Any, "private"))]),
            "ExternRule modifiers must be a list",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", modifiers=[cast(Any, object())])]),
            "ExternRule modifiers item must be RuleModifier or string",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", modifiers=cast(Any, [""]))]),
            "ExternRule modifier name cannot be empty",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", modifiers=cast(Any, ["bad"]))]),
            "Invalid rule modifier",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", namespace=cast(Any, 123))]),
            "ExternRule namespace must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport(cast(Any, 123))]),
            "ExternImport module_path must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("")]),
            "ExternImport module_path cannot be empty",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", alias=cast(Any, 123))]),
            "ExternImport alias must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", rules=cast(Any, "Rule"))]),
            "ExternImport rules must be a list of strings",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", rules=[cast(Any, object())])]),
            "ExternImport rules must be a list of strings",
        ),
        (
            YaraFile(namespaces=[ExternNamespace(cast(Any, 123))]),
            "ExternNamespace name must be a string",
        ),
        (
            YaraFile(namespaces=[ExternNamespace("")]),
            "ExternNamespace name cannot be empty",
        ),
        (
            YaraFile(namespaces=[ExternNamespace("corp", extern_rules=cast(Any, "Rule"))]),
            "ExternNamespace extern_rules must be a list",
        ),
        (
            YaraFile(namespaces=[ExternNamespace("corp", extern_rules=[cast(Any, object())])]),
            "ExternNamespace extern_rules item must be ExternRule",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_extern_fields(
    malformed_file: YaraFile,
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            ExternRuleReference(cast(Any, 123)),
            "ExternRuleReference rule_name must be a string",
        ),
        (
            ExternRuleReference(""),
            "ExternRuleReference rule_name cannot be empty",
        ),
        (
            ExternRuleReference("ExternalRule", namespace=cast(Any, 123)),
            "ExternRuleReference namespace must be a string",
        ),
        (
            ExternRuleReference("ExternalRule", namespace=""),
            "ExternRuleReference namespace cannot be empty",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_extern_reference_fields(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_extern_reference", condition=condition)])

    with pytest.raises((TypeError, ValueError), match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("string_def", "message"),
    [
        (
            PlainString("$a", value="abc", modifiers=cast(Any, "wide")),
            "PlainString modifiers must be a list",
        ),
        (
            PlainString("$a", value="abc", modifiers=[cast(Any, object())]),
            "PlainString modifiers item must be StringModifier or string",
        ),
        (
            PlainString("$a", value="abc", modifiers=[""]),
            "PlainString modifier name cannot be empty",
        ),
        (PlainString("$a", value="abc", modifiers=["badmod"]), "Unknown string modifier"),
        (RegexString("$r", regex="abc", modifiers=["badmod"]), "Unknown string modifier"),
        (
            HexString("$h", tokens=[HexByte(0x41)], modifiers=["badmod"]),
            "Unknown string modifier",
        ),
        (
            PlainString("$a", value="abc", modifiers=["nocase", "nocase"]),
            "Duplicate string modifier 'nocase'",
        ),
        (
            PlainString("$a", value="abc", modifiers=["base64", "xor"]),
            "String modifier 'xor' cannot be combined with 'base64'",
        ),
        (
            PlainString("$a", value="abc", modifiers=["xor", "nocase"]),
            "String modifier 'nocase' cannot be combined with 'xor'",
        ),
        (
            PlainString("$a", value="abc", modifiers=["i"]),
            "Unsupported string modifier: i",
        ),
        (
            HexString("$h", tokens=[HexByte(0x41)], modifiers=["wide"]),
            "String modifier 'wide' is not valid on hex strings",
        ),
        (
            RegexString("$r", regex="abc", modifiers=["base64"]),
            "String modifier 'base64' is not valid on regex strings",
        ),
        (
            PlainString("$a", value="abc", modifiers=[StringModifier(cast(Any, "xor"))]),
            "StringModifier modifier_type must be a StringModifierType",
        ),
        (
            PlainString(
                "$a",
                value="abc",
                modifiers=[StringModifier(StringModifierType.XOR, cast(Any, object()))],
            ),
            "StringModifier value must be a string, number, tuple, or null",
        ),
        (
            PlainString(
                "$a",
                value="abc",
                modifiers=[StringModifier(StringModifierType.NOCASE, 1)],
            ),
            "String modifier 'nocase' does not accept a value",
        ),
        (
            PlainString(
                "$a",
                value="abc",
                modifiers=[StringModifier(StringModifierType.XOR, 999)],
            ),
            "xor value must be a byte",
        ),
        (
            PlainString(
                "$a",
                value="abc",
                modifiers=[StringModifier(StringModifierType.XOR, (5, 1))],
            ),
            "xor range value must be ascending",
        ),
        (
            PlainString(
                "$a",
                value="abc",
                modifiers=[StringModifier(StringModifierType.XOR, (0, 999))],
            ),
            "xor range value must contain byte bounds",
        ),
        (
            PlainString(
                "$a",
                value="abc",
                modifiers=[StringModifier(StringModifierType.BASE64, "short")],
            ),
            "base64 alphabet must be 64 bytes",
        ),
        (
            PlainString(
                "$a",
                value="abc",
                modifiers=[StringModifier(StringModifierType.BASE64, 1)],
            ),
            "base64 value must be a string",
        ),
    ],
)
def test_direct_yarafile_analysis_rejects_invalid_string_modifiers(
    string_def: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                "bad_string_modifier",
                strings=[string_def],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises((TypeError, ValueError), match=message):
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


@pytest.mark.parametrize(
    ("field_name", "value", "operation", "message"),
    [
        ("rules", cast(Any, "bad"), "get_all_rules", "YaraFile rules must be a list or tuple"),
        (
            "rules",
            [cast(Any, object())],
            "get_all_rules",
            "YaraFile rules must contain Rule nodes",
        ),
        (
            "pragmas",
            cast(Any, "bad"),
            "get_pragma_by_type",
            "YaraFile pragmas must be a list or tuple",
        ),
        (
            "pragmas",
            [cast(Any, object())],
            "has_include_once",
            "YaraFile pragmas must contain Pragma nodes",
        ),
        (
            "extern_rules",
            cast(Any, "bad"),
            "get_extern_rule_by_name",
            "YaraFile extern_rules must be a list or tuple",
        ),
        (
            "extern_rules",
            [cast(Any, object())],
            "get_extern_rule_by_name",
            "YaraFile extern_rules must contain ExternRule nodes",
        ),
        (
            "namespaces",
            cast(Any, "bad"),
            "get_extern_rule_by_name",
            "YaraFile namespaces must be a list or tuple",
        ),
        (
            "namespaces",
            [cast(Any, object())],
            "get_extern_rule_by_name",
            "YaraFile namespaces must contain ExternNamespace nodes",
        ),
    ],
)
def test_yarafile_helpers_reject_invalid_internal_containers(
    field_name: str,
    value: Any,
    operation: str,
    message: str,
) -> None:
    file_node = YaraFile()
    setattr(file_node, field_name, value)

    with pytest.raises(TypeError, match=message):
        if operation == "get_all_rules":
            file_node.get_all_rules()
        elif operation == "get_pragma_by_type":
            file_node.get_pragma_by_type(PragmaType.PRAGMA)
        elif operation == "has_include_once":
            file_node.has_include_once()
        else:
            file_node.get_extern_rule_by_name("Remote")


@pytest.mark.parametrize(
    ("file_node", "operation", "message"),
    [
        (
            YaraFile(rules=[Rule(cast(Any, object()))]),
            "get_all_rules",
            "Rule name must be a string",
        ),
        (
            YaraFile(pragmas=[Pragma(cast(Any, "bad"), "vendor")]),
            "get_pragma_by_type",
            "Pragma type must be a PragmaType",
        ),
        (
            YaraFile(extern_rules=[ExternRule(cast(Any, 123))]),
            "get_extern_rule_by_name",
            "ExternRule name must be a string",
        ),
        (
            YaraFile(namespaces=[ExternNamespace("corp", extern_rules=cast(Any, "Rule"))]),
            "get_extern_rule_by_name",
            "ExternNamespace extern_rules must be a list",
        ),
        (
            YaraFile(namespaces=[ExternNamespace("corp", extern_rules=[cast(Any, object())])]),
            "get_extern_rule_by_name",
            "ExternNamespace extern_rules item must be ExternRule",
        ),
        (
            YaraFile(namespaces=[ExternNamespace("corp", [ExternRule(cast(Any, 123))])]),
            "get_extern_rule_by_name",
            "ExternRule name must be a string",
        ),
    ],
)
def test_yarafile_helpers_reject_invalid_child_state(
    file_node: YaraFile,
    operation: str,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        if operation == "get_all_rules":
            file_node.get_all_rules()
        elif operation == "get_pragma_by_type":
            file_node.get_pragma_by_type(PragmaType.PRAGMA)
        else:
            file_node.get_extern_rule_by_name("Remote")


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
