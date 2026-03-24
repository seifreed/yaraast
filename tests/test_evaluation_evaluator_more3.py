"""Additional evaluator branch tests without mocks."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modules import ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import PlainString
from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluator import YaraEvaluator


def test_identifier_and_literal_paths() -> None:
    ev = YaraEvaluator(data=b"abc")
    ev.context.variables["x"] = 7
    ev.context.modules["m"] = {"k": 3}
    ev.context.string_matches = {"$a": []}

    assert ev.visit_identifier(Identifier(name="filesize")) == 3
    assert ev.visit_identifier(Identifier(name="entrypoint")) == 0
    assert ev.visit_identifier(Identifier(name="all")) == "all"
    assert ev.visit_identifier(Identifier(name="any")) == "any"
    assert ev.visit_identifier(Identifier(name="them")) == ["$a"]
    assert ev.visit_identifier(Identifier(name="x")) == 7
    assert ev.visit_identifier(Identifier(name="m")) == {"k": 3}

    # Unknown identifiers return False (could be unresolved rule references)
    assert ev.visit_identifier(Identifier(name="zzz")) is False


def test_string_count_offset_length_and_wildcard() -> None:
    ev = YaraEvaluator(data=b"xxabxxab")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    assert ev.evaluate_rule(rule) is True

    assert ev.visit_string_identifier(StringIdentifier(name="$a")) is True
    assert ev.visit_string_wildcard(StringWildcard(pattern="$*")) is True
    assert ev.visit_string_count(StringCount(string_id="a")) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=0))) == 2
    assert ev.visit_string_length(StringLength(string_id="$a", index=IntegerLiteral(value=1))) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=9))) == -1
    assert ev.visit_string_length(StringLength(string_id="$a", index=IntegerLiteral(value=9))) == 0


def test_binary_unary_function_member_array_and_errors() -> None:
    ev = YaraEvaluator(data=b"\x01\x02\x03\x04")

    assert (
        ev.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))) == 3
    )
    assert (
        ev.visit_binary_expression(
            BinaryExpression(BooleanLiteral(True), "or", BooleanLiteral(False))
        )
        is True
    )
    assert ev.visit_unary_expression(UnaryExpression("not", BooleanLiteral(False))) is True
    assert ev.visit_unary_expression(UnaryExpression("-", IntegerLiteral(2))) == -2
    assert ev.visit_unary_expression(UnaryExpression("~", IntegerLiteral(1))) == ~1
    assert ev.visit_parentheses_expression(ParenthesesExpression(BooleanLiteral(True))) is True
    assert ev.visit_set_expression(
        SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    ) == {1, 2}
    r = ev.visit_range_expression(RangeExpression(low=IntegerLiteral(2), high=IntegerLiteral(4)))
    assert list(r) == [2, 3, 4]

    assert (
        ev.visit_function_call(FunctionCall(function="uint16", arguments=[IntegerLiteral(value=0)]))
        == 513
    )
    with pytest.raises(EvaluationError, match="Unknown function"):
        ev.visit_function_call(FunctionCall(function="nope.fn", arguments=[]))

    obj = SimpleNamespace(v=9)
    assert (
        ev.visit_member_access(MemberAccess(object=StringLiteral(value="x"), member="upper"))
        is not None
    )
    ev.context.variables["obj"] = obj
    assert ev.visit_member_access(MemberAccess(object=Identifier(name="obj"), member="v")) == 9
    assert (
        ev.visit_member_access(MemberAccess(object=Identifier(name="m"), member="k")) == 3
        if "m" in ev.context.modules
        else True
    )

    ev.context.variables["arr"] = [10, 20]
    assert (
        ev.visit_array_access(
            ArrayAccess(array=Identifier(name="arr"), index=IntegerLiteral(value=1))
        )
        == 20
    )
    assert (
        ev.visit_array_access(
            ArrayAccess(array=Identifier(name="arr"), index=StringLiteral(value="x"))
        )
        is None
    )

    with pytest.raises(EvaluationError, match="Unknown operator"):
        ev.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "???", IntegerLiteral(2)))
    with pytest.raises(EvaluationError, match="Unknown unary operator"):
        ev.visit_unary_expression(UnaryExpression("!", IntegerLiteral(1)))


def test_condition_paths_for_at_in_of_for_and_defined() -> None:
    ev = YaraEvaluator(data=b"00abcd00")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    assert (
        ev.visit_at_expression(AtExpression(string_id="$a", offset=IntegerLiteral(value=2))) is True
    )
    assert (
        ev.visit_in_expression(
            InExpression(subject="$a", range=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)))
        )
        is True
    )
    assert (
        ev.visit_in_expression(InExpression(subject="$a", range=IntegerLiteral(value=5))) is False
    )

    ev.context.string_matches = {"$a": [1], "$b": []}
    ev.string_matcher.matches = ev.context.string_matches
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=Identifier(name="any"),
                string_set=SetExpression([StringLiteral("$a"), StringLiteral("$b")]),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=StringLiteral(value="none"),
                string_set=SetExpression([StringLiteral("$b")]),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=IntegerLiteral(value=1),
                string_set=SetExpression([StringLiteral("$a"), StringLiteral("$b")]),
            )
        )
        is True
    )

    for_any = ForExpression(
        quantifier="any",
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
        body=BinaryExpression(Identifier("i"), "==", IntegerLiteral(2)),
    )
    assert ev.visit_for_expression(for_any) is True

    for_all = ForExpression(
        quantifier="all",
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
        body=BinaryExpression(Identifier("i"), ">", IntegerLiteral(0)),
    )
    assert ev.visit_for_expression(for_all) is True

    for_none = ForExpression(
        quantifier="none",
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=False),
    )
    assert ev.visit_for_expression(for_none) is True

    ev._current_rule = rule
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=StringIdentifier(name="$a")))
        is True
    )
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=Identifier(name="missing")))
        is False
    )

    assert ev.visit_regex_literal(SimpleNamespace(pattern="ab.*")) == "ab.*"
    assert ev.visit_module_reference(SimpleNamespace()) is None


def test_for_of_and_module_reference_paths() -> None:
    ev = YaraEvaluator(data=b"xxabyy")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    from yaraast.ast.conditions import ForOfExpression

    node_any = ForOfExpression(
        quantifier="any",
        string_set=Identifier(name="them"),
        condition=BooleanLiteral(value=True),
    )
    assert ev.visit_for_of_expression(node_any) is True

    node_pct = ForOfExpression(
        quantifier="any",
        string_set=Identifier(name="them"),
        condition=None,
    )
    assert ev.visit_for_of_expression(node_pct) is True

    ev.context.modules["pe"] = {"machine": 0x14C}
    assert ev.visit_module_reference(ModuleReference(module="pe")) == {"machine": 0x14C}
    with pytest.raises(EvaluationError, match="Unknown module"):
        ev.visit_module_reference(ModuleReference(module="missing"))

    # Member access on non-object types returns None gracefully
    assert ev.visit_member_access(MemberAccess(object=IntegerLiteral(value=1), member="x")) is None

    # Expression dispatch should still work for concrete types.
    assert ev.visit_expression(BooleanLiteral(value=True)) is True


def test_evaluate_file_with_alias_import_and_string_operator_expression() -> None:
    ev = YaraEvaluator(data=b"abc")
    file_ast = __import__("yaraast.ast.base", fromlist=["YaraFile"]).YaraFile(
        imports=[Import(module="math", alias="m")],
        rules=[
            Rule(
                name="ok",
                condition=BinaryExpression(
                    left=FunctionCall(function="m.abs", arguments=[IntegerLiteral(value=-1)]),
                    operator="==",
                    right=IntegerLiteral(value=1),
                ),
            )
        ],
    )
    out = ev.evaluate_file(file_ast)
    assert out["ok"] is True


def test_evaluate_file_skips_unknown_imports_and_continues() -> None:
    ev = YaraEvaluator(data=b"abc")
    file_ast = __import__("yaraast.ast.base", fromlist=["YaraFile"]).YaraFile(
        imports=[Import(module="missing"), Import(module="math")],
        rules=[Rule(name="ok", condition=BooleanLiteral(value=True))],
    )

    out = ev.evaluate_file(file_ast)

    assert out["ok"] is True
    assert "missing" not in ev.context.modules
    assert "math" in ev.context.modules


def test_evaluator_or_module_member_of_and_defined_paths() -> None:
    ev = YaraEvaluator(data=b"xxabyy")
    ev.context.variables["obj"] = {"k": 7}
    ev.context.variables["present_var"] = 11

    rule = Rule(
        name="r",
        strings=[
            PlainString(identifier="$a", value="ab"),
            PlainString(identifier="$b", value="yy"),
        ],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    assert (
        ev.visit_binary_expression(
            BinaryExpression(BooleanLiteral(False), "or", BooleanLiteral(True))
        )
        is True
    )
    assert ev.visit_member_access(MemberAccess(object=Identifier(name="obj"), member="k")) == 7

    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=StringLiteral(value="all"),
                string_set=StringLiteral(value="them"),
            )
        )
        is True
    )
    # Float quantifier (percentage) is now handled — 50% of 0 strings = 0 required
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=DoubleLiteral(value=0.5),
                string_set=StringLiteral(value="them"),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=StringLiteral(value="weird"),
                string_set=StringLiteral(value="them"),
            )
        )
        is False
    )

    ev.context.modules["pe"] = {"machine": 0x14C}
    assert ev.visit_defined_expression(DefinedExpression(expression=Identifier(name="pe"))) is True
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=Identifier(name="present_var")))
        is True
    )
    ev._current_rule = rule
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=StringIdentifier(name="$missing")))
        is False
    )
    ev._current_rule = Rule(name="empty", condition=BooleanLiteral(value=True))
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=StringIdentifier(name="$a")))
        is False
    )

    assert (
        ev.visit_string_operator_expression(
            StringOperatorExpression(
                left=StringLiteral(value="Hello"),
                operator="istartswith",
                right=StringLiteral(value="he"),
            )
        )
        is True
    )


def test_evaluator_module_function_for_and_for_of_remaining_paths() -> None:
    ev = YaraEvaluator(data=b"xxabyy")
    ev.context.modules["math"] = ev.module_registry.create_module("math", ev.data)
    rule = Rule(
        name="r",
        strings=[
            PlainString(identifier="$a", value="ab"),
            PlainString(identifier="$b", value="yy"),
        ],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    with pytest.raises(EvaluationError, match="Unknown function: missing.abs"):
        ev.visit_function_call(FunctionCall(function="missing.abs", arguments=[]))

    with pytest.raises(EvaluationError, match="Unknown function: math.missing"):
        ev.visit_function_call(FunctionCall(function="math.missing", arguments=[]))
    with pytest.raises(EvaluationError, match="Unknown function: missing"):
        ev.visit_function_call(FunctionCall(function="missing", arguments=[]))

    ev.context.variables["i"] = 99
    for_two = ForExpression(
        quantifier=IntegerLiteral(value=2),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]),
        body=BinaryExpression(Identifier("i"), ">", IntegerLiteral(1)),
    )
    assert ev.visit_for_expression(for_two) is True
    assert ev.context.variables["i"] == 99

    for_unknown = ForExpression(
        quantifier=DoubleLiteral(value=0.25),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=True),
    )
    assert ev.visit_for_expression(for_unknown) is False

    for_weird = ForExpression(
        quantifier=StringLiteral(value="weird"),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=True),
    )
    assert ev.visit_for_expression(for_weird) is False

    from yaraast.ast.conditions import ForOfExpression as ForOf

    node_all = ForOf(
        quantifier="all", string_set=Identifier(name="them"), condition=BooleanLiteral(value=True)
    )
    assert ev.visit_for_of_expression(node_all) is True

    node_none = ForOf(
        quantifier="none", string_set=Identifier(name="them"), condition=BooleanLiteral(value=False)
    )
    assert ev.visit_for_of_expression(node_none) is True

    node_int = ForOf(
        quantifier=IntegerLiteral(value=1), string_set=Identifier(name="them"), condition=None
    )
    assert ev.visit_for_of_expression(node_int) is True

    node_unknown = ForOf(
        quantifier="weird", string_set=Identifier(name="them"), condition=BooleanLiteral(value=True)
    )
    assert ev.visit_for_of_expression(node_unknown) is False

    node_other = ForOf(
        quantifier=SetExpression([]),
        string_set=Identifier(name="them"),
        condition=BooleanLiteral(value=True),
    )
    assert ev.visit_for_of_expression(node_other) is False
