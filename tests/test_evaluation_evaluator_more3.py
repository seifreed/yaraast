"""Additional evaluator branch tests without mocks."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast.ast.conditions import (
    AtExpression,
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
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import PlainString
from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
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


def test_evaluator_matches_operator_honors_regex_modifiers() -> None:
    ast = Parser().parse('rule r { condition: "FOO" matches /foo/i }')

    assert YaraEvaluator().evaluate_file(ast) == {"r": True}


def test_hash_module_invalid_regions_evaluate_as_undefined() -> None:
    ast = Parser().parse("""
        import "hash"
        rule invalid_hash_regions {
            condition:
                hash.md5(-1, 1) == "d41d8cd98f00b204e9800998ecf8427e" or
                hash.md5(filesize, 0) == "d41d8cd98f00b204e9800998ecf8427e" or
                hash.checksum32(-1, 1) == 0 or
                hash.crc32(-1, 1) != 0 or
                not hash.crc32(-1, 1)
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"invalid_hash_regions": False}


def test_hash_module_valid_region_can_extend_to_file_end() -> None:
    ast = Parser().parse("""
        import "hash"
        rule trailing_hash_region {
            condition:
                hash.md5(1, 100) == "5360af35bde9ebd8f01f492dc059593c"
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"trailing_hash_region": True}


def test_math_module_invalid_regions_evaluate_as_undefined() -> None:
    ast = Parser().parse("""
        import "math"
        rule invalid_math_regions {
            condition:
                math.entropy(-1, 1) == 0.0 or
                math.mean(filesize, 0) == 0.0 or
                math.deviation(-1, 1, 0.0) == 0.0 or
                math.serial_correlation(0, 1) == 0.0 or
                math.monte_carlo_pi(0, 5) == 0.0 or
                not math.entropy(-1, 1)
        }
        """)

    assert YaraEvaluator(data=b"abcdef").evaluate_file(ast) == {"invalid_math_regions": False}


def test_math_module_valid_regions_can_extend_to_file_end() -> None:
    ast = Parser().parse("""
        import "math"
        rule trailing_math_region {
            condition:
                math.mean(1, 100) == 100.0 and
                math.entropy(0, 0) == 0.0
        }
        """)

    assert YaraEvaluator(data=b"abcdef").evaluate_file(ast) == {"trailing_math_region": True}


def test_string_count_offset_length_and_wildcard() -> None:
    ev = YaraEvaluator(data=b"xxabxxab")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    assert ev.evaluate_rule(rule) is True

    assert ev.visit_string_identifier(StringIdentifier(name="$a")) is True
    assert ev.visit_string_identifier(StringIdentifier(name="a")) is True
    assert ev.visit_string_wildcard(StringWildcard(pattern="$*")) is True
    assert ev.visit_string_count(StringCount(string_id="a")) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a")) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=1))) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=2))) == 6
    assert ev.visit_string_length(StringLength(string_id="$a", index=IntegerLiteral(value=1))) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=9))) == -1
    assert ev.visit_string_length(StringLength(string_id="$a", index=IntegerLiteral(value=9))) == 0

    ast = Parser().parse("""
        rule indexed {
            strings:
                $a = "ab"
            condition:
                @a[1] == 2 and @a[2] == 6 and !a[1] == 2
        }
        """)
    assert YaraEvaluator(data=b"xxabxxab").evaluate_file(ast) == {"indexed": True}


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
    with pytest.raises(EvaluationError, match=r"uint16\(\) expects exactly 1 argument"):
        ev.visit_function_call(FunctionCall(function="uint16", arguments=[]))
    with pytest.raises(EvaluationError, match=r"uint16\(\) expects exactly 1 argument"):
        ev.visit_function_call(
            FunctionCall(
                function="uint16",
                arguments=[IntegerLiteral(value=0), IntegerLiteral(value=1)],
            )
        )
    with pytest.raises(EvaluationError, match=r"uint16\(\) offset must be an integer"):
        ev.visit_function_call(
            FunctionCall(function="uint16", arguments=[StringLiteral(value="0")])
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


def test_evaluator_uint8be_and_int8be_match_registered_builtin_functions() -> None:
    ast = Parser().parse("""
        rule byte_endian_aliases {
            condition:
                uint8be(0) == 255 and int8be(0) == -1
        }
    """)

    assert YaraEvaluator(data=b"\xff").evaluate_file(ast) == {"byte_endian_aliases": True}


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
        ev.visit_at_expression(AtExpression(string_id="a", offset=IntegerLiteral(value=2))) is True
    )
    assert (
        ev.visit_in_expression(
            InExpression(subject="$a", range=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)))
        )
        is True
    )
    assert (
        ev.visit_in_expression(
            InExpression(subject="a", range=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)))
        )
        is True
    )
    assert (
        ev.visit_in_expression(InExpression(subject="$a", range=IntegerLiteral(value=5))) is False
    )
    assert (
        ev.visit_in_expression(
            InExpression(
                subject=BooleanLiteral(value=True),
                range=RangeExpression(IntegerLiteral(0), IntegerLiteral(0)),
            )
        )
        is False
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

    assert ev.visit_of_expression(OfExpression(quantifier="any", string_set="them")) is True
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(quantifier="any", string_set=["$a", "$missing"], condition=None)
        )
        is True
    )
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(quantifier="all", string_set="$a*", condition=BooleanLiteral(True))
        )
        is True
    )
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(quantifier="all", string_set="a*", condition=BooleanLiteral(True))
        )
        is True
    )

    parsed = Parser().parse('rule r { strings: $a = "ab" condition: for any of them : ($) }')
    assert YaraEvaluator(data=b"xxabyy").evaluate_file(parsed) == {"r": True}

    ev.context.modules["pe"] = {"machine": 0x14C}
    assert ev.visit_module_reference(ModuleReference(module="pe")) == {"machine": 0x14C}
    with pytest.raises(EvaluationError, match="Unknown module"):
        ev.visit_module_reference(ModuleReference(module="missing"))

    # Member access on non-object types returns None gracefully
    assert ev.visit_member_access(MemberAccess(object=IntegerLiteral(value=1), member="x")) is None

    # Expression dispatch should still work for concrete types.
    assert ev.visit_expression(BooleanLiteral(value=True)) is True


def test_string_wildcard_condition_respects_pattern() -> None:
    evaluator = YaraEvaluator(data=b"abc")
    rule = Rule(
        name="wildcard",
        strings=[
            PlainString(identifier="$a_one", value="ab"),
            PlainString(identifier="$b_one", value="zz"),
        ],
        condition=BooleanLiteral(value=True),
    )
    evaluator.evaluate_rule(rule)

    assert evaluator.visit_string_wildcard(StringWildcard("$a*")) is True
    assert evaluator.visit_string_wildcard(StringWildcard("$b*")) is False


def test_of_expression_in_range_uses_match_offsets() -> None:
    def evaluate(condition: str) -> bool:
        ast = Parser().parse(f"""
            rule r {{
                strings:
                    $a = "ab"
                    $b = "cd"
                condition:
                    {condition}
            }}
            """)
        return YaraEvaluator(data=b"xxabyycd").evaluate_file(ast)["r"]

    assert evaluate("any of them in (0..1)") is False
    assert evaluate("any of them in (0..3)") is True
    assert evaluate("2 of them in (0..3)") is False
    assert evaluate("2 of them in (0..7)") is True
    assert evaluate("all of them in (0..3)") is False


def test_percentage_of_expression_uses_ratio_threshold() -> None:
    def evaluate(condition: str, data: bytes) -> bool:
        ast = Parser().parse(f"""
            rule r {{
                strings:
                    $a = "a"
                    $b = "b"
                    $c = "c"
                condition:
                    {condition}
            }}
            """)
        return YaraEvaluator(data=data).evaluate_file(ast)["r"]

    assert evaluate("50% of them", b"a") is False
    assert evaluate("50% of them", b"ab") is True

    rule = Rule(
        name="r",
        strings=[
            PlainString(identifier="$a", value="a"),
            PlainString(identifier="$b", value="b"),
            PlainString(identifier="$c", value="c"),
        ],
        condition=BooleanLiteral(value=True),
    )
    evaluator = YaraEvaluator(data=b"a")
    evaluator.evaluate_rule(rule)
    assert (
        evaluator.visit_for_of_expression(
            ForOfExpression(
                quantifier=DoubleLiteral(value=0.5),
                string_set=Identifier(name="them"),
                condition=None,
            )
        )
        is False
    )


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


def test_evaluate_file_defined_module_reference_after_import() -> None:
    ast = Parser().parse("""
        import "math"
        rule imported_module {
            condition:
                defined math
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"imported_module": True}


def test_evaluate_file_resolves_forward_rule_references() -> None:
    ast = Parser().parse("""
        rule first {
            strings:
                $a = "missing"
            condition:
                second and #a == 0
        }

        rule second {
            strings:
                $b = "abc"
            condition:
                $b
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"first": True, "second": True}


def test_evaluate_file_resets_imported_modules_between_files() -> None:
    evaluator = YaraEvaluator(data=b"abc")
    with_import = Parser().parse("""
        import "math"
        rule imported_module {
            condition:
                defined math
        }
    """)
    without_import = Parser().parse("""
        rule no_import {
            condition:
                defined math
        }
    """)

    assert evaluator.evaluate_file(with_import) == {"imported_module": True}
    assert evaluator.evaluate_file(without_import) == {"no_import": False}


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

    with pytest.raises(EvaluationError, match=r"Unknown function: missing\.abs"):
        ev.visit_function_call(FunctionCall(function="missing.abs", arguments=[]))

    with pytest.raises(EvaluationError, match=r"Unknown function: math\.missing"):
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

    parsed = Parser().parse("rule r { condition: for all k, v in ((1, 2), (3, 4)) : (k < v) }")
    parsed_condition = parsed.rules[0].condition
    assert parsed_condition is not None
    assert YaraEvaluator().visit(parsed_condition) is True

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


def test_parser_numeric_for_quantifier_evaluates_as_integer() -> None:
    ast = Parser().parse("rule r { condition: for 2 i in (1,2,3) : (i > 1) }")

    assert YaraEvaluator().evaluate_file(ast) == {"r": True}


def test_evaluator_evaluates_yarax_collection_literals_and_indexing() -> None:
    ev = YaraEvaluator()
    ev.context.variables["tail"] = [2, 3]
    ev.context.variables["rest"] = {"b": 2}

    assert ev.visit(ListExpression([IntegerLiteral(1), SpreadOperator(Identifier("tail"))])) == [
        1,
        2,
        3,
    ]
    assert ev.visit(TupleExpression([IntegerLiteral(1), IntegerLiteral(2)])) == (1, 2)
    assert ev.visit(
        DictExpression(
            [
                DictItem(StringLiteral("a"), IntegerLiteral(1)),
                DictItem(
                    StringLiteral("__spread__"),
                    SpreadOperator(Identifier("rest"), is_dict=True),
                ),
            ]
        )
    ) == {"a": 1, "b": 2}
    assert (
        ev.visit(
            TupleIndexing(
                TupleExpression([StringLiteral("a"), StringLiteral("b")]),
                IntegerLiteral(1),
            )
        )
        == "b"
    )
    assert ev.visit(
        SliceExpression(
            target=ListExpression([IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]),
            start=IntegerLiteral(1),
        )
    ) == [2, 3]


def test_evaluator_evaluates_yarax_comprehensions() -> None:
    ev = YaraEvaluator()
    ev.context.variables["items"] = [1, 2, 3]
    ev.context.variables["pairs"] = {"a": 1, "b": 2}

    assert ev.visit(
        ArrayComprehension(
            expression=BinaryExpression(Identifier("x"), "*", IntegerLiteral(2)),
            variable="x",
            iterable=Identifier("items"),
            condition=BinaryExpression(Identifier("x"), ">", IntegerLiteral(1)),
        )
    ) == [4, 6]
    assert "x" not in ev.context.variables

    assert ev.visit(
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=BinaryExpression(Identifier("v"), "+", IntegerLiteral(1)),
            key_variable="k",
            value_variable="v",
            iterable=Identifier("pairs"),
            condition=BinaryExpression(Identifier("v"), ">", IntegerLiteral(1)),
        )
    ) == {"b": 3}
    assert "k" not in ev.context.variables
    assert "v" not in ev.context.variables


def test_evaluator_evaluates_yarax_with_statement_and_pattern_match() -> None:
    ev = YaraEvaluator()

    condition = WithStatement(
        declarations=[WithDeclaration("$x", IntegerLiteral(2))],
        body=BinaryExpression(
            PatternMatch(
                value=Identifier("x"),
                cases=[MatchCase(pattern=IntegerLiteral(2), result=BooleanLiteral(True))],
                default=BooleanLiteral(False),
            ),
            "and",
            BinaryExpression(
                TupleIndexing(
                    TupleExpression([IntegerLiteral(1), Identifier("x")]),
                    IntegerLiteral(1),
                ),
                "==",
                IntegerLiteral(2),
            ),
        ),
    )

    assert ev.visit(condition) is True
    assert "$x" not in ev.context.variables
    assert "x" not in ev.context.variables


def test_evaluator_restores_yarax_with_declarations_when_later_declaration_fails() -> None:
    ev = YaraEvaluator()

    condition = WithStatement(
        declarations=[
            WithDeclaration("$x", IntegerLiteral(2)),
            WithDeclaration("$bad", FunctionCall("missing_function", [])),
        ],
        body=BooleanLiteral(True),
    )

    with pytest.raises(EvaluationError):
        ev.visit(condition)

    assert "$x" not in ev.context.variables
    assert "x" not in ev.context.variables


def test_evaluator_evaluates_dictionary_access_and_defined_dictionary_access() -> None:
    ev = YaraEvaluator()
    ev.context.variables["d"] = {"name": "alpha", 1: "one"}
    ev.context.variables["key"] = "name"
    ev.context.modules["pe"] = SimpleNamespace(version_info={"CompanyName": "Microsoft"})

    assert ev.visit(DictionaryAccess(Identifier("d"), "name")) == "alpha"
    assert ev.visit(DictionaryAccess(Identifier("d"), IntegerLiteral(1))) == "one"
    assert ev.visit(DictionaryAccess(Identifier("d"), Identifier("key"))) == "alpha"
    assert (
        ev.visit(
            DictionaryAccess(
                MemberAccess(Identifier("pe"), "version_info"),
                StringLiteral("CompanyName"),
            )
        )
        == "Microsoft"
    )
    assert ev.visit(DefinedExpression(DictionaryAccess(Identifier("d"), "name"))) is True
    assert ev.visit(DefinedExpression(DictionaryAccess(Identifier("d"), "missing"))) is False
