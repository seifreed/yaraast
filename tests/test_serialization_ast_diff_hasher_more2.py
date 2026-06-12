"""Additional branch coverage for AstHasher helper visitors (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    RegexLiteral,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import CustomPragma, InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.serialization.ast_diff_hasher import AstHasher
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)


class _AcceptNode(ASTNode):
    def __init__(self, visit_method: str, **attrs: object) -> None:
        self._visit_method = visit_method
        for key, value in attrs.items():
            setattr(self, key, value)

    def accept(self, visitor: AstHasher) -> str:
        visit = cast(Callable[[object], str], getattr(visitor, self._visit_method))
        return visit(self)


class _FalsyIntegerLiteral(IntegerLiteral):
    def __bool__(self) -> bool:
        return False


def test_ast_hasher_string_and_expression_helpers() -> None:
    hasher = AstHasher()

    hex_repr = hasher.visit_hex_string(
        _AcceptNode(
            "visit_hex_string",
            identifier="$h",
            tokens=[
                _AcceptNode("visit_hex_byte", value="AA"),
                _AcceptNode("visit_hex_wildcard"),
                _AcceptNode("visit_hex_jump", min_jump=2, max_jump=4),
            ],
            modifiers=[_AcceptNode("visit_string_modifier", name="ascii", value=None)],
        ),
    )
    assert "HexString($h" in hex_repr
    assert ",False,Mod(ascii,None)" in hex_repr
    assert "Byte(AA)" in hex_repr
    assert "Wildcard()" in hex_repr
    assert "Jump(2,4)" in hex_repr
    assert "Mod(ascii,None)" in hex_repr

    regex_repr = hasher.visit_regex_string(
        _AcceptNode(
            "visit_regex_string",
            identifier="$r",
            regex="abc.*",
            modifiers=[_AcceptNode("visit_string_modifier", name="nocase", value=None)],
        ),
    )
    assert "RegexString($r,abc.*" in regex_repr
    assert ",False,Mod(nocase,None)" in regex_repr

    anonymous_plain = hasher.visit_plain_string(
        SimpleNamespace(identifier="$anon_1", value="x", modifiers=[], is_anonymous=True)
    )
    named_plain = hasher.visit_plain_string(
        SimpleNamespace(identifier="$anon_1", value="x", modifiers=[], is_anonymous=False)
    )
    assert anonymous_plain != named_plain

    binary_repr = hasher.visit_binary_expression(
        _AcceptNode(
            "visit_binary_expression",
            left=_AcceptNode("visit_integer_literal", value=1),
            operator="+",
            right=_AcceptNode("visit_integer_literal", value=2),
        ),
    )
    assert binary_repr == "Binary(Int(1),+,Int(2))"

    assert hasher.visit_string_wildcard(SimpleNamespace(pattern="$a*")) == "$a*"
    assert hasher.visit_string_definition(SimpleNamespace(identifier="$a")) == (
        "StringDef($a,False)"
    )
    assert (
        hasher.visit_string_definition(SimpleNamespace(identifier="$anon_1", is_anonymous=True))
        == "StringDef($anon_1,True)"
    )
    assert hasher.visit_hex_token(SimpleNamespace()) == "Token()"
    assert hasher.visit_hex_negated_byte(SimpleNamespace(value="4D")) == "NegatedByte(4D)"
    assert hasher.visit_hex_alternative(SimpleNamespace()) == "Alt()"
    assert hasher.visit_hex_alternative(HexAlternative([0x90, "91"])) == "Alt(Byte(144)|Byte(91))"
    assert hasher.visit_hex_alternative(HexAlternative([[0x90], [HexByte("91")]])) == (
        "Alt(Byte(144)|Byte(91))"
    )
    assert hasher.visit_hex_nibble(SimpleNamespace(high="A", value="F")) == "Nibble(A,F)"
    assert hasher.visit_expression(SimpleNamespace()) == "Expr()"
    assert hasher.visit(Rule("present", condition=_FalsyIntegerLiteral(0))) != hasher.visit(
        Rule("present", condition=None)
    )
    assert hasher.visit(ForOfExpression("any", Identifier("them"), _FalsyIntegerLiteral(0))) == (
        "ForOf(any,Id(them),Int(0))"
    )
    assert hasher.visit_string_count(SimpleNamespace(string_id="a")) == "Count(a)"
    assert hasher.visit_string_offset(SimpleNamespace(string_id="a")) == "Offset(a)"
    assert hasher.visit_string_length(SimpleNamespace(string_id="a")) == "Length(a)"
    assert hasher.visit_double_literal(SimpleNamespace(value=1.5)) == "Double(1.5)"
    assert hasher.visit_regex_literal(SimpleNamespace(pattern="x+", modifiers="i")) == "Regex(x+,i)"

    unary = hasher.visit_unary_expression(
        _AcceptNode(
            "visit_unary_expression",
            operator="-",
            operand=_AcceptNode("visit_integer_literal", value=9),
        ),
    )
    assert unary == "Unary(-,Int(9))"

    parens = hasher.visit_parentheses_expression(
        _AcceptNode(
            "visit_parentheses_expression",
            expression=_AcceptNode("visit_identifier", name="x"),
        ),
    )
    assert parens == "Parens(Id(x))"

    set_repr = hasher.visit_set_expression(
        _AcceptNode(
            "visit_set_expression",
            elements=[
                _AcceptNode("visit_identifier", name="a"),
                _AcceptNode("visit_identifier", name="b"),
            ],
        ),
    )
    assert set_repr == "Set(Id(a)|Id(b))"

    range_repr = hasher.visit_range_expression(
        _AcceptNode(
            "visit_range_expression",
            low=_AcceptNode("visit_integer_literal", value=1),
            high=_AcceptNode("visit_integer_literal", value=3),
        ),
    )
    assert range_repr == "Range(Int(1),Int(3))"

    fn_repr = hasher.visit_function_call(
        _AcceptNode(
            "visit_function_call",
            function="f",
            arguments=[_AcceptNode("visit_integer_literal", value=7)],
        ),
    )
    assert fn_repr == "Call(:f,Int(7))"

    arr_repr = hasher.visit_array_access(
        _AcceptNode(
            "visit_array_access",
            array=_AcceptNode("visit_identifier", name="arr"),
            index=_AcceptNode("visit_integer_literal", value=0),
        ),
    )
    assert arr_repr == "Array(Id(arr),Int(0))"

    member_repr = hasher.visit_member_access(
        _AcceptNode(
            "visit_member_access",
            object=_AcceptNode("visit_identifier", name="obj"),
            member="x",
        ),
    )
    assert member_repr == "Member(Id(obj),x)"


def test_ast_hasher_condition_misc_and_extern_paths() -> None:
    hasher = AstHasher()

    assert hasher.visit_condition(SimpleNamespace()) == "Condition()"
    assert (
        hasher.visit_for_expression(
            _AcceptNode(
                "visit_for_expression",
                quantifier="any",
                variable="i",
                iterable=_AcceptNode("visit_identifier", name="xs"),
                body=_AcceptNode("visit_boolean_literal", value=True),
            ),
        )
        == "For(any,i,Id(xs),Bool(True))"
    )
    assert (
        hasher.visit_for_expression(
            _AcceptNode(
                "visit_for_expression",
                quantifier=_AcceptNode("visit_integer_literal", value=2),
                variable="i",
                iterable=_AcceptNode("visit_identifier", name="xs"),
                body=_AcceptNode("visit_boolean_literal", value=True),
            ),
        )
        == "For(Int(2),i,Id(xs),Bool(True))"
    )

    assert (
        hasher.visit_for_of_expression(
            _AcceptNode(
                "visit_for_of_expression",
                quantifier="all",
                string_set=_AcceptNode("visit_identifier", name="them"),
                condition=_AcceptNode("visit_boolean_literal", value=False),
            ),
        )
        == "ForOf(all,Id(them),Bool(False))"
    )
    assert (
        hasher.visit_for_of_expression(
            _AcceptNode(
                "visit_for_of_expression",
                quantifier="all",
                string_set=_AcceptNode("visit_identifier", name="them"),
                condition=None,
            ),
        )
        == "ForOf(all,Id(them),)"
    )

    assert (
        hasher.visit_at_expression(
            _AcceptNode(
                "visit_at_expression",
                string_id="$a",
                offset=_AcceptNode("visit_integer_literal", value=10),
            ),
        )
        == "At($a,Int(10))"
    )
    assert (
        hasher.visit_at_expression(
            AtExpression(
                string_id=OfExpression(IntegerLiteral(1), Identifier("them")),
                offset=IntegerLiteral(10),
            )
        )
        == "At(Of(Int(1),Id(them)),Int(10))"
    )

    in_expr = InExpression(subject="$a", range=IntegerLiteral(value=5))
    assert hasher.visit_in_expression(in_expr) == "In($a,Int(5))"

    of_with_nodes = hasher.visit_of_expression(
        _AcceptNode(
            "visit_of_expression",
            quantifier=_AcceptNode("visit_identifier", name="any"),
            string_set=_AcceptNode("visit_identifier", name="them"),
        ),
    )
    assert of_with_nodes == "Of(Id(any),Id(them))"

    of_with_plain_values = hasher.visit_of_expression(
        _AcceptNode(
            "visit_of_expression",
            quantifier="all",
            string_set="them",
        ),
    )
    assert of_with_plain_values == "Of(all,them)"

    assert hasher.visit_meta(SimpleNamespace(key="author", value="me")) == "Meta(author,str:me)"
    assert hasher.visit_module_reference(SimpleNamespace(module="pe")) == "ModRef(pe)"

    dict_repr = hasher.visit_dictionary_access(
        _AcceptNode(
            "visit_dictionary_access",
            object=_AcceptNode("visit_identifier", name="obj"),
            key="k",
        ),
    )
    assert dict_repr == "Dict(Id(obj),k)"

    assert hasher.visit_comment(SimpleNamespace(text="c", is_multiline=False)) == "Comment(c,False)"
    comment_group = hasher.visit_comment_group(
        _AcceptNode(
            "visit_comment_group",
            comments=[_AcceptNode("visit_comment", text="a", is_multiline=False)],
        ),
    )
    assert comment_group == "CommentGroup(Comment(a,False))"

    defined = hasher.visit_defined_expression(
        _AcceptNode(
            "visit_defined_expression", expression=_AcceptNode("visit_identifier", name="x")
        ),
    )
    assert defined == "Defined(Id(x))"

    str_op = hasher.visit_string_operator_expression(
        _AcceptNode(
            "visit_string_operator_expression",
            left=_AcceptNode("visit_identifier", name="a"),
            operator="contains",
            right=_AcceptNode("visit_string_literal", value="b"),
        ),
    )
    assert str_op == "StrOp(Id(a),contains,Str(b))"

    assert hasher.visit_extern_import(SimpleNamespace(module="m")) == "ExternImport(m,None,)"
    assert hasher.visit_extern_import(SimpleNamespace()) == "ExternImport(,None,)"
    assert hasher.visit_extern_namespace(SimpleNamespace(name="ns")) == "ExternNamespace(ns,)"
    assert hasher.visit_extern_namespace(SimpleNamespace()) == "ExternNamespace(,)"
    assert hasher.visit_extern_rule(SimpleNamespace(name="r")) == "ExternRule(r,,None)"
    assert hasher.visit_extern_rule(SimpleNamespace()) == "ExternRule(,,None)"
    assert (
        hasher.visit_extern_rule_reference(SimpleNamespace(name="rr")) == "ExternRuleRef(rr,None)"
    )
    assert hasher.visit_extern_rule_reference(SimpleNamespace()) == "ExternRuleRef(,None)"
    assert hasher.visit_in_rule_pragma(SimpleNamespace(pragma="opt")) == "InRulePragma(opt)"
    assert hasher.visit_in_rule_pragma(SimpleNamespace()) == "InRulePragma()"
    assert hasher.visit_pragma(SimpleNamespace(directive="enable")) == "Pragma(enable)"
    assert hasher.visit_pragma(SimpleNamespace()) == "Pragma()"

    pragma_block = hasher.visit_pragma_block(
        _AcceptNode(
            "visit_pragma_block",
            pragmas=[
                _AcceptNode("visit_pragma", directive="a"),
                _AcceptNode("visit_pragma", directive="b"),
            ],
        ),
    )
    assert pragma_block == "PragmaBlock(Pragma(a),Pragma(b),None)"
    assert hasher.visit_pragma_block(SimpleNamespace()) == "PragmaBlock(,None)"

    # Keep one simple literal visitor exercised explicitly.
    assert hasher.visit_string_literal(StringLiteral(value="ok")) == "Str(ok)"


@pytest.mark.parametrize(
    ("pragma", "error_type", "message"),
    [
        (Pragma(cast(Any, "bad"), "vendor"), TypeError, "Pragma type must be a PragmaType"),
        (
            Pragma(PragmaType.PRAGMA, "vendor", scope=cast(Any, "file")),
            TypeError,
            "Pragma scope must be a PragmaScope",
        ),
        (
            CustomPragma("vendor", parameters=cast(Any, [])),
            TypeError,
            "Pragma parameters must be a dictionary",
        ),
    ],
)
def test_ast_hasher_rejects_invalid_real_pragma_state(
    pragma: Pragma,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        AstHasher().visit_pragma(pragma)


def test_ast_hasher_rejects_invalid_real_string_modifier_state() -> None:
    modifier = StringModifier.from_name_value("base64", "alphabet")
    modifier.value = cast(Any, object())

    with pytest.raises(TypeError, match="StringModifier value must be"):
        AstHasher().visit_string_modifier(modifier)


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("rules", cast(Any, "bad"), "YaraFile rules must be a list or tuple"),
        ("rules", [cast(Any, object())], "YaraFile rules must contain Rule nodes"),
    ],
)
def test_ast_hasher_rejects_invalid_real_yarafile_state(
    field_name: str,
    value: Any,
    message: str,
) -> None:
    ast = YaraFile()
    setattr(ast, field_name, value)

    with pytest.raises(TypeError, match=message):
        AstHasher().visit_yara_file(ast)


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("modifiers", cast(Any, False), "Rule modifiers must be a list"),
        ("tags", [cast(Any, object())], "Rule tags must contain Tag nodes"),
        ("meta", cast(Any, False), "Rule meta must be a list or tuple"),
        ("strings", [cast(Any, object())], "Rule strings must contain StringDefinition nodes"),
    ],
)
def test_ast_hasher_rejects_invalid_real_rule_state(
    field_name: str,
    value: Any,
    message: str,
) -> None:
    rule = Rule("bad")
    setattr(rule, field_name, value)

    with pytest.raises(TypeError, match=message):
        AstHasher().visit_rule(rule)


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (PlainString(cast(Any, 123), "x"), "String identifier must be a string"),
        (
            PlainString("$a", cast(Any, object())),
            "Plain string value must be a string or bytes",
        ),
        (HexString("$h", tokens=cast(Any, "bad")), "HexString tokens must be a list or tuple"),
        (
            HexString("$h", tokens=[cast(Any, object())]),
            r"HexString\.tokens must contain AST nodes",
        ),
        (RegexString("$r", cast(Any, object())), "Regex string pattern must be a string"),
    ],
)
def test_ast_hasher_rejects_invalid_real_string_state(
    node: PlainString | HexString | RegexString,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        AstHasher().visit(node)


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (HexByte(cast(Any, 0x100)), TypeError, "HexByte value must be a byte"),
        (
            HexNegatedByte(cast(Any, "??")),
            TypeError,
            "HexNegatedByte value must be a byte or negated nibble",
        ),
        (
            HexJump(cast(Any, -1), 2),
            TypeError,
            "HexJump min_jump must be a non-negative integer",
        ),
        (HexJump(3, 1), TypeError, "HexJump min_jump cannot exceed max_jump"),
        (
            HexNibble(cast(Any, "high"), "A"),
            TypeError,
            "HexNibble high must be a boolean",
        ),
        (HexNibble(True, cast(Any, "AA")), TypeError, "HexNibble value must be a nibble"),
        (HexAlternative([[]]), ValueError, "HexAlternative branches must not be empty"),
        (
            HexAlternative([HexJump(1, None)]),
            ValueError,
            "Unbounded HexJump is not allowed inside hex alternatives",
        ),
    ],
)
def test_ast_hasher_rejects_invalid_real_hex_token_state(
    node: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        AstHasher().visit(node)


@pytest.mark.parametrize(
    ("string_set", "message"),
    [
        (StringLiteral(cast(Any, False)), "String literal value must be a string"),
        (StringIdentifier(cast(Any, False)), "String identifier must be a string"),
        (StringWildcard(cast(Any, False)), "String wildcard pattern must be a string"),
    ],
)
def test_ast_hasher_rejects_non_string_string_set_values(
    string_set: Any,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        AstHasher().visit(OfExpression("any", [string_set]))


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (Identifier(""), ValueError, "Identifier name cannot be empty"),
        (
            StringIdentifier(cast(Any, False)),
            TypeError,
            "String identifier must be a string",
        ),
        (StringWildcard(""), ValueError, "String wildcard pattern cannot be empty"),
        (
            IntegerLiteral(cast(Any, True)),
            TypeError,
            "Integer literal value must be an integer",
        ),
        (
            DoubleLiteral(cast(Any, float("inf"))),
            ValueError,
            "Double literal value must be finite",
        ),
        (
            StringLiteral(cast(Any, False)),
            TypeError,
            "String literal value must be a string",
        ),
        (RegexLiteral(""), ValueError, "RegexLiteral pattern must not be empty"),
        (
            BooleanLiteral(cast(Any, 1)),
            TypeError,
            "Boolean literal value must be a boolean",
        ),
        (
            BinaryExpression(cast(Any, "left"), "+", IntegerLiteral(1)),
            TypeError,
            "BinaryExpression.left must be an Expression",
        ),
        (
            FunctionCall("fn", [cast(Any, "arg")]),
            TypeError,
            "Function arguments must contain AST nodes",
        ),
    ],
)
def test_ast_hasher_rejects_invalid_real_expression_state(
    node: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        AstHasher().visit(node)


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (
            ForExpression("any", "", Identifier("xs"), BooleanLiteral(True)),
            ValueError,
            "ForExpression variable must not be empty",
        ),
        (
            ForOfExpression("", ["$a"]),
            ValueError,
            "ForOfExpression quantifier must not be empty",
        ),
        (
            AtExpression("", IntegerLiteral(1)),
            ValueError,
            "AtExpression string_id must not be empty",
        ),
        (
            InExpression("$a", cast(Any, "bad")),
            TypeError,
            "'in' range must be an AST node",
        ),
        (
            OfExpression("any", []),
            ValueError,
            "OfExpression string_set must contain values",
        ),
    ],
)
def test_ast_hasher_rejects_invalid_real_condition_state(
    node: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        AstHasher().visit(node)


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (
            WithStatement([cast(Any, object())], BooleanLiteral(True)),
            "WithStatement declarations must contain WithDeclaration nodes",
        ),
        (
            WithDeclaration(cast(Any, object()), IntegerLiteral(1)),
            "Local variable name must be a string",
        ),
        (
            ArrayComprehension(variable=cast(Any, object())),
            "Local variable name must be a string",
        ),
        (
            ListExpression([cast(Any, object())]),
            "ListExpression elements must contain Expression nodes",
        ),
        (
            DictExpression([cast(Any, object())]),
            "DictExpression items must contain DictItem nodes",
        ),
        (DictItem(cast(Any, object()), StringLiteral("v")), "DictItem.key must be an AST node"),
        (
            SliceExpression(cast(Any, object())),
            "SliceExpression.target must be an AST node",
        ),
        (
            LambdaExpression(cast(Any, "x"), Identifier("x")),
            "LambdaExpression parameters must be a list or tuple",
        ),
        (
            PatternMatch(Identifier("x"), [cast(Any, object())]),
            "PatternMatch cases must contain MatchCase nodes",
        ),
        (
            MatchCase(cast(Any, object()), BooleanLiteral(True)),
            "MatchCase.pattern must be an AST node",
        ),
        (
            SpreadOperator(Identifier("items"), cast(Any, "dict")),
            "SpreadOperator is_dict must be a boolean",
        ),
    ],
)
def test_ast_hasher_rejects_invalid_real_yarax_state(node: Any, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        AstHasher().visit(node)


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (Meta(cast(Any, object()), "value"), TypeError, "Meta key must be a string"),
        (ModuleReference(""), ValueError, "ModuleReference module cannot be empty"),
        (
            DictionaryAccess(cast(Any, object()), "key"),
            TypeError,
            "DictionaryAccess.object must be an Expression",
        ),
        (Comment(cast(Any, object())), TypeError, "Comment text must be a string"),
        (
            CommentGroup([cast(Any, object())]),
            TypeError,
            "CommentGroup comments must contain Comment nodes",
        ),
        (
            DefinedExpression(cast(Any, object())),
            TypeError,
            "DefinedExpression expression must be an AST expression",
        ),
        (
            StringOperatorExpression(Identifier("a"), "", StringLiteral("b")),
            ValueError,
            "StringOperatorExpression operator must not be empty",
        ),
        (ExternImport(""), ValueError, "ExternImport module_path cannot be empty"),
        (
            ExternNamespace("ns", [cast(Any, object())]),
            TypeError,
            "ExternNamespace extern_rules item must be ExternRule",
        ),
        (ExternRule(""), ValueError, "ExternRule name cannot be empty"),
        (
            ExternRuleReference(""),
            ValueError,
            "ExternRuleReference rule_name cannot be empty",
        ),
        (
            InRulePragma(cast(Any, object())),
            TypeError,
            "InRulePragma pragma must be a Pragma",
        ),
        (
            PragmaBlock([cast(Any, object())]),
            TypeError,
            "PragmaBlock pragmas must contain Pragma nodes",
        ),
    ],
)
def test_ast_hasher_rejects_invalid_real_misc_state(
    node: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        AstHasher().visit(node)


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (Import(""), ValueError, "Import module cannot be empty"),
        (Include(cast(Any, object())), TypeError, "Include path must be a string"),
        (Tag(""), ValueError, "Tag name cannot be empty"),
        (
            StringDefinition(cast(Any, object())),
            TypeError,
            "String identifier must be a string",
        ),
    ],
)
def test_ast_hasher_rejects_invalid_real_leaf_state(
    node: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        AstHasher().visit(node)


def test_ast_hasher_yarax_expression_nodes() -> None:
    hasher = AstHasher()

    list_expr = ListExpression([IntegerLiteral(1), SpreadOperator(Identifier("rest"))])
    assert hasher.visit(list_expr) == "List(Int(1)|Spread(Id(rest),False))"

    dict_expr = DictExpression(
        [
            DictItem(Identifier("key"), StringLiteral("value")),
            DictItem(Identifier("base"), SpreadOperator(Identifier("defaults"), True)),
        ]
    )
    assert hasher.visit(dict_expr) == (
        "DictExpr(DictItem(Id(key),Str(value))|" "DictItem(Id(base),Spread(Id(defaults),True)))"
    )

    assert hasher.visit(TupleExpression([IntegerLiteral(1), IntegerLiteral(2)])) == (
        "Tuple(Int(1)|Int(2))"
    )
    assert (
        hasher.visit(
            TupleIndexing(
                TupleExpression([IntegerLiteral(1), IntegerLiteral(2)]), IntegerLiteral(0)
            )
        )
        == "TupleIndex(Tuple(Int(1)|Int(2)),Int(0))"
    )
    assert hasher.visit(SliceExpression(Identifier("xs"), stop=IntegerLiteral(2))) == (
        "Slice(Id(xs),,Int(2),)"
    )
    assert (
        hasher.visit(
            LambdaExpression(["x"], BinaryExpression(Identifier("x"), ">", IntegerLiteral(0)))
        )
        == "Lambda(x,Binary(Id(x),>,Int(0)))"
    )
    assert (
        hasher.visit(
            ArrayComprehension(
                expression=Identifier("x"),
                variable="x",
                iterable=Identifier("xs"),
                condition=BinaryExpression(Identifier("x"), ">", IntegerLiteral(0)),
            )
        )
        == "ArrayComp(Id(x),x,Id(xs),Binary(Id(x),>,Int(0)))"
    )
    assert (
        hasher.visit(
            DictComprehension(
                key_expression=Identifier("k"),
                value_expression=Identifier("v"),
                key_variable="k",
                value_variable="v",
                iterable=Identifier("mapping"),
            )
        )
        == "DictComp(Id(k),Id(v),k,v,Id(mapping),)"
    )

    pattern = PatternMatch(
        value=Identifier("xs"),
        cases=[MatchCase(IntegerLiteral(1), BooleanLiteral(True))],
        default=BooleanLiteral(False),
    )
    assert hasher.visit(pattern) == "Match(Id(xs),Case(Int(1),Bool(True)),Bool(False))"

    with_statement = WithStatement(
        declarations=[WithDeclaration("xs", list_expr)],
        body=pattern,
    )
    assert hasher.visit(with_statement) == (
        "With(WithDecl(xs,List(Int(1)|Spread(Id(rest),False))),"
        "Match(Id(xs),Case(Int(1),Bool(True)),Bool(False)))"
    )


def test_ast_hasher_preserves_extended_file_fields() -> None:
    hasher = AstHasher()
    ast = YaraFile(
        extern_imports=[ExternImport(module_path="external.yar", alias="ext", rules=["R1"])],
        extern_rules=[
            ExternRule(
                name="R1",
                modifiers=[RuleModifier.from_string("private")],
                namespace="ns",
            )
        ],
        pragmas=[CustomPragma(name="vendor", parameters={"level": "strict"})],
        namespaces=[ExternNamespace(name="ns", extern_rules=[ExternRule(name="Nested")])],
        rules=[
            Rule(
                name="r1",
                condition=BooleanLiteral(True),
                pragmas=[
                    InRulePragma(
                        pragma=Pragma(PragmaType.PRAGMA, "optimize", ["fast"]),
                        position="before_condition",
                    )
                ],
            )
        ],
    )
    ast_with_other_alias = YaraFile(
        extern_imports=[ExternImport(module_path="external.yar", alias="other", rules=["R1"])],
        extern_rules=ast.extern_rules,
        pragmas=ast.pragmas,
        namespaces=ast.namespaces,
        rules=ast.rules,
    )

    ast_repr = hasher.visit_yara_file(ast)

    assert "ExternImport(external.yar,ext,R1)" in ast_repr
    assert "ExternRule(R1,private,ns)" in ast_repr
    assert "Pragma(custom,vendor,,file,parameters=level=strict)" in ast_repr
    assert "ExternNamespace(ns,ExternRule(Nested,,None))" in ast_repr
    assert "InRulePragma(Pragma(pragma,optimize,fast,file,),before_condition)" in ast_repr
    assert hasher.hash_ast(ast) != hasher.hash_ast(ast_with_other_alias)
