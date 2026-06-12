"""Additional branch coverage for AstHasher helper visitors (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.modifiers import RuleModifier, StringModifier
from yaraast.ast.pragmas import CustomPragma, InRulePragma, Pragma, PragmaType
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexAlternative, HexByte
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
    "string_set",
    [
        StringLiteral(cast(Any, False)),
        StringIdentifier(cast(Any, False)),
        StringWildcard(cast(Any, False)),
    ],
)
def test_ast_hasher_rejects_non_string_string_set_values(string_set: Any) -> None:
    with pytest.raises(TypeError, match="String reference must be a string"):
        AstHasher().visit(OfExpression("any", [string_set]))


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
