"""Additional branch coverage for AstHasher helper visitors (no mocks)."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.ast.conditions import InExpression
from yaraast.ast.expressions import StringLiteral
from yaraast.serialization.ast_diff_hasher import AstHasher


class _AcceptNode:
    def __init__(self, visit_method: str, **attrs) -> None:
        self._visit_method = visit_method
        for key, value in attrs.items():
            setattr(self, key, value)

    def accept(self, visitor):
        return getattr(visitor, self._visit_method)(self)


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
    assert hasher.visit_string_definition(SimpleNamespace(identifier="$a")) == "StringDef($a)"
    assert hasher.visit_hex_token(SimpleNamespace()) == "Token()"
    assert hasher.visit_hex_alternative(SimpleNamespace()) == "Alt()"
    assert hasher.visit_hex_nibble(SimpleNamespace(high="A", value="F")) == "Nibble(A,F)"
    assert hasher.visit_expression(SimpleNamespace()) == "Expr()"
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
    assert fn_repr == "Call(f,Int(7))"

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

    in_expr = InExpression(subject="$a", range=_AcceptNode("visit_integer_literal", value=5))
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

    assert hasher.visit_meta(SimpleNamespace(key="author", value="me")) == "Meta(author,me)"
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

    assert hasher.visit_extern_import(SimpleNamespace(module="m")) == "ExternImport(m)"
    assert hasher.visit_extern_import(SimpleNamespace()) == "ExternImport()"
    assert hasher.visit_extern_namespace(SimpleNamespace(name="ns")) == "ExternNamespace(ns)"
    assert hasher.visit_extern_namespace(SimpleNamespace()) == "ExternNamespace()"
    assert hasher.visit_extern_rule(SimpleNamespace(name="r")) == "ExternRule(r)"
    assert hasher.visit_extern_rule(SimpleNamespace()) == "ExternRule()"
    assert hasher.visit_extern_rule_reference(SimpleNamespace(name="rr")) == "ExternRuleRef(rr)"
    assert hasher.visit_extern_rule_reference(SimpleNamespace()) == "ExternRuleRef()"
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
    assert pragma_block == "PragmaBlock(Pragma(a),Pragma(b))"
    assert hasher.visit_pragma_block(SimpleNamespace()) == "PragmaBlock()"

    # Keep one simple literal visitor exercised explicitly.
    assert hasher.visit_string_literal(StringLiteral(value="ok")) == "Str(ok)"
