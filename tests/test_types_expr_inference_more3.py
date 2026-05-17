"""Additional real coverage for expression type inference."""

from __future__ import annotations

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
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modules import DictionaryAccess
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.parser.source import parse_yara_source
from yaraast.types._expr_inference import ExpressionTypeInference, _TypeBaseVisitor
from yaraast.types._registry import (
    ArrayType,
    BooleanType,
    DictionaryType,
    IntegerType,
    StringType,
    TypeEnvironment,
    UnknownType,
)
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    MatchCase,
    PatternMatch,
    SliceExpression,
    TupleIndexing,
)


def test_type_base_visitor_default_methods_return_unknown() -> None:
    visitor = _TypeBaseVisitor()

    nodes = [
        Comment("x"),
        CommentGroup([Comment("x")]),
        DefinedExpression(expression=IntegerLiteral(value=1)),
        StringOperatorExpression(
            left=StringLiteral(value="a"),
            operator="contains",
            right=StringLiteral(value="b"),
        ),
        ExternImport(module_path="ext"),
        ExternNamespace(name="ns"),
        ExternRule(name="r"),
        ExternRuleReference(rule_name="r"),
        InRulePragma(pragma=Pragma(pragma_type=PragmaType.PRAGMA, name="pragma")),
        Pragma(pragma_type=PragmaType.PRAGMA, name="pragma"),
        PragmaBlock(pragmas=[]),
    ]

    for node in nodes:
        out = visitor.visit(node)
        if isinstance(node, DefinedExpression | StringOperatorExpression):
            assert isinstance(out, BooleanType)
        else:
            assert isinstance(out, UnknownType)


def test_expr_inference_reports_undefined_string_variants() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert isinstance(inf.infer(StringCount(string_id="missing")), UnknownType)
    assert isinstance(inf.infer(StringOffset(string_id="missing")), UnknownType)
    assert isinstance(inf.infer(StringLength(string_id="missing")), UnknownType)

    assert "Undefined string: $missing" in inf.errors[0]
    assert "Undefined string: $missing" in inf.errors[1]
    assert "Undefined string: $missing" in inf.errors[2]


def test_expr_inference_reports_undefined_raw_string_references() -> None:
    env = TypeEnvironment()
    env.add_string("$a")

    at_inf = ExpressionTypeInference(env)
    assert isinstance(
        at_inf.infer(AtExpression(string_id="$missing", offset=IntegerLiteral(value=0))),
        BooleanType,
    )
    assert "Undefined string: $missing" in at_inf.errors

    in_inf = ExpressionTypeInference(env)
    assert isinstance(
        in_inf.infer(
            InExpression(
                subject="$missing",
                range=RangeExpression(IntegerLiteral(value=0), IntegerLiteral(value=1)),
            )
        ),
        BooleanType,
    )
    assert "Undefined string: $missing" in in_inf.errors

    of_inf = ExpressionTypeInference(env)
    assert isinstance(
        of_inf.infer(OfExpression(quantifier="any", string_set=["$a", "$missing"])),
        BooleanType,
    )
    assert "Undefined string: $missing" in of_inf.errors

    for_of_inf = ExpressionTypeInference(env)
    assert isinstance(
        for_of_inf.infer(
            ForOfExpression(
                quantifier="any",
                string_set=SetExpression([StringLiteral("$a"), StringLiteral("$missing")]),
                condition=BooleanLiteral(value=True),
            )
        ),
        BooleanType,
    )
    assert "Undefined string: $missing" in for_of_inf.errors


def test_expr_inference_string_length_invalid_index_reports_error() -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    inf = ExpressionTypeInference(env)

    out = inf.infer(StringLength(string_id="a", index=StringLiteral(value="bad")))
    assert isinstance(out, IntegerType)
    assert "String length index must be integer" in inf.errors[0]


def test_expr_inference_validates_plain_dictionary_key_type() -> None:
    env = TypeEnvironment()
    env.define("by_number", DictionaryType(IntegerType(), StringType()))
    inf = ExpressionTypeInference(env)

    out = inf.infer(DictionaryAccess(object=Identifier("by_number"), key="name"))

    assert isinstance(out, StringType)
    assert any("Dictionary key must be integer, got string" in error for error in inf.errors)


def test_expr_inference_comparison_and_builtin_function_paths() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    cmp_out = inf.infer(
        BinaryExpression(
            left=StringLiteral(value="x"),
            operator="==",
            right=IntegerLiteral(value=1),
        ),
    )
    assert isinstance(cmp_out, BooleanType)
    assert "Incompatible types for '=='" in inf.errors[0]

    right_bad = inf.infer(
        BinaryExpression(
            left=BooleanLiteral(value=True),
            operator="and",
            right=IntegerLiteral(value=1),
        ),
    )
    assert isinstance(right_bad, BooleanType)
    assert any("Right operand of 'and' must be boolean" in e for e in inf.errors)


def test_expr_inference_validates_module_function_argument_types() -> None:
    env = TypeEnvironment()
    env.add_module("math")
    inf = ExpressionTypeInference(env)

    out = inf.infer(FunctionCall(function="math.abs", arguments=[StringLiteral("bad")]))

    assert isinstance(out, IntegerType)
    assert any(
        "Argument 'x' to function 'abs' must be integer, got string" in e for e in inf.errors
    )


def test_expr_inference_accepts_hash_checksum32_function() -> None:
    env = TypeEnvironment()
    env.add_module("hash")
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        FunctionCall(function="hash.checksum32", arguments=[IntegerLiteral(0), IntegerLiteral(1)])
    )

    assert isinstance(out, IntegerType)
    assert inf.errors == []


def test_expr_inference_validates_builtin_reader_offset_type() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    out = inf.infer(FunctionCall(function="uint32", arguments=[StringLiteral("bad")]))

    assert isinstance(out, IntegerType)
    assert any(
        "Argument 'offset' to function 'uint32' must be integer, got string" in e
        for e in inf.errors
    )


def test_expr_inference_visits_unresolved_function_arguments() -> None:
    for function_name in ("unknown", "pe.unknown"):
        env = TypeEnvironment()
        env.add_module("pe")
        inf = ExpressionTypeInference(env)

        out = inf.infer(
            FunctionCall(
                function=function_name,
                arguments=[
                    BinaryExpression(
                        left=StringLiteral("bad"),
                        operator="+",
                        right=IntegerLiteral(1),
                    ),
                ],
            ),
        )

        assert isinstance(out, UnknownType)
        assert any("Left operand of '+' must be numeric, got string" in e for e in inf.errors)


def test_expr_inference_visits_defined_expression_operand() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        DefinedExpression(
            BinaryExpression(
                left=StringLiteral("bad"),
                operator="+",
                right=IntegerLiteral(1),
            ),
        ),
    )

    assert isinstance(out, BooleanType)
    assert any("Left operand of '+' must be numeric, got string" in e for e in inf.errors)


def test_expr_inference_validates_string_operator_expression_operands() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        StringOperatorExpression(
            left=IntegerLiteral(1),
            operator="icontains",
            right=StringLiteral("x"),
        ),
    )

    assert isinstance(out, BooleanType)
    assert any(
        "Left operand of 'icontains' must be string-like or array, got integer" in e
        for e in inf.errors
    )


def test_expr_inference_reports_invalid_comprehension_iterables() -> None:
    env = TypeEnvironment()

    range_inf = ExpressionTypeInference(env)
    range_out = range_inf.infer(
        ArrayComprehension(
            expression=BinaryExpression(
                left=Identifier("i"),
                operator="+",
                right=IntegerLiteral(1),
            ),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)),
        ),
    )
    assert isinstance(range_out, ArrayType)
    assert isinstance(range_out.element_type, IntegerType)
    assert range_inf.errors == []

    array_inf = ExpressionTypeInference(env)
    array_out = array_inf.infer(
        ArrayComprehension(
            expression=Identifier("x"),
            variable="x",
            iterable=StringLiteral("bad"),
        ),
    )
    assert isinstance(array_out, ArrayType)
    assert any("Cannot iterate over type: string" in e for e in array_inf.errors)

    dict_inf = ExpressionTypeInference(env)
    dict_out = dict_inf.infer(
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=Identifier("v"),
            key_variable="k",
            value_variable="v",
            iterable=StringLiteral("bad"),
        ),
    )
    assert isinstance(dict_out, DictionaryType)
    assert any("Cannot iterate over type: string" in e for e in dict_inf.errors)


def test_expr_inference_binds_multi_variable_for_dictionary_items() -> None:
    env = TypeEnvironment()
    env.define("pairs", DictionaryType(StringType(), IntegerType()))
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        ForExpression(
            quantifier="all",
            variable="k,v",
            iterable=Identifier("pairs"),
            body=BinaryExpression(
                left=BinaryExpression(Identifier("k"), "==", StringLiteral("name")),
                operator="or",
                right=BinaryExpression(Identifier("v"), ">", IntegerLiteral(0)),
            ),
        ),
    )

    assert isinstance(out, BooleanType)
    assert inf.errors == []


def test_expr_inference_binds_dict_comprehension_value_variable_type() -> None:
    env = TypeEnvironment()
    env.define("pairs", DictionaryType(StringType(), IntegerType()))
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=BinaryExpression(Identifier("v"), "+", IntegerLiteral(1)),
            key_variable="k",
            value_variable="v",
            iterable=Identifier("pairs"),
        ),
    )

    assert isinstance(out, DictionaryType)
    assert isinstance(out.key_type, StringType)
    assert isinstance(out.value_type, IntegerType)
    assert inf.errors == []


def test_expr_inference_visits_pattern_match_case_patterns() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        PatternMatch(
            value=StringLiteral("value"),
            cases=[
                MatchCase(
                    pattern=BinaryExpression(
                        left=StringLiteral("bad"),
                        operator="+",
                        right=IntegerLiteral(1),
                    ),
                    result=IntegerLiteral(1),
                ),
            ],
            default=IntegerLiteral(0),
        ),
    )

    assert isinstance(out, IntegerType)
    assert any("Left operand of '+' must be numeric, got string" in e for e in inf.errors)


def test_expr_inference_reports_invalid_index_and_slice_targets() -> None:
    env = TypeEnvironment()

    tuple_inf = ExpressionTypeInference(env)
    tuple_out = tuple_inf.infer(
        TupleIndexing(
            tuple_expr=IntegerLiteral(1),
            index=IntegerLiteral(0),
        ),
    )
    assert isinstance(tuple_out, UnknownType)
    assert any("Cannot index non-tuple type: integer" in e for e in tuple_inf.errors)

    slice_inf = ExpressionTypeInference(env)
    slice_out = slice_inf.infer(
        SliceExpression(
            target=IntegerLiteral(1),
            start=IntegerLiteral(0),
            stop=IntegerLiteral(1),
        ),
    )
    assert isinstance(slice_out, UnknownType)
    assert any("Cannot slice non-array or string type: integer" in e for e in slice_inf.errors)


def test_expr_inference_at_in_and_of_error_paths() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert isinstance(
        inf.infer(AtExpression(string_id="$a", offset=StringLiteral(value="bad"))),
        BooleanType,
    )
    assert any("Offset in 'at' expression must be integer" in e for e in inf.errors)

    assert isinstance(
        inf.infer(InExpression(subject="$a", range=IntegerLiteral(value=1))),
        BooleanType,
    )
    assert any("'in' expression requires range" in e for e in inf.errors)

    assert isinstance(
        inf.infer(
            InExpression(
                subject=OfExpression(
                    quantifier=BooleanLiteral(value=True),
                    string_set=IntegerLiteral(value=1),
                ),
                range=RangeExpression(IntegerLiteral(value=0), IntegerLiteral(value=1)),
            )
        ),
        BooleanType,
    )
    assert any("'of' quantifier must be string, integer, or percentage" in e for e in inf.errors)
    assert any("'of' requires string set" in e for e in inf.errors)

    assert isinstance(
        inf.infer(
            OfExpression(
                quantifier=BooleanLiteral(value=True),
                string_set=IntegerLiteral(value=1),
            ),
        ),
        BooleanType,
    )
    assert any("'of' quantifier must be string, integer, or percentage" in e for e in inf.errors)
    assert any("'of' requires string set" in e for e in inf.errors)

    percent_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        percent_of.infer(
            OfExpression(
                quantifier=DoubleLiteral(value=0.5),
                string_set=Identifier(name="them"),
            )
        ),
        BooleanType,
    )
    assert percent_of.errors == []

    for percentage in (0.0, 1.01):
        bad_percent_of = ExpressionTypeInference(TypeEnvironment())
        assert isinstance(
            bad_percent_of.infer(
                OfExpression(
                    quantifier=DoubleLiteral(value=percentage),
                    string_set=Identifier(name="them"),
                )
            ),
            BooleanType,
        )
        assert any(
            "'of' percentage quantifier must be between 1 and 100" in e
            for e in bad_percent_of.errors
        )


def test_expr_inference_validates_for_expression_quantifier_type() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    assert isinstance(
        inf.infer(
            ForExpression(
                quantifier=BooleanLiteral(value=True),
                variable="i",
                iterable=RangeExpression(
                    low=IntegerLiteral(value=1),
                    high=IntegerLiteral(value=2),
                ),
                body=BooleanLiteral(value=True),
            )
        ),
        BooleanType,
    )

    assert any("'for' quantifier must be string or integer" in e for e in inf.errors)


def test_expr_inference_helper_and_branch_edges() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert inf._normalize_string_id("a") == "$a"
    assert inf._normalize_string_id("$a") == "$a"

    env.modules.add("")
    assert inf._resolve_module_type("") is None

    env2 = TypeEnvironment()
    env2.add_module("ghost")
    assert ExpressionTypeInference(env2)._resolve_module_type("ghost") is None

    high_bad = ExpressionTypeInference(TypeEnvironment())
    out = high_bad.infer(
        InExpression(
            subject="$a",
            range=RangeExpression(
                low=IntegerLiteral(value=1),
                high=StringLiteral(value="x"),
            ),
        ),
    )
    assert isinstance(out, BooleanType)
    assert any("Range high bound must be integer" in e for e in high_bad.errors)

    dict_env = TypeEnvironment()
    from yaraast.types._registry import DictionaryType

    dict_env.define("d", DictionaryType(StringType(), IntegerType()))
    dict_out = ExpressionTypeInference(dict_env).infer(
        DictionaryAccess(object=Identifier(name="d"), key="plain-key"),
    )
    assert isinstance(dict_out, IntegerType)

    set_env = TypeEnvironment()
    set_env.add_string("$a")
    fo = ExpressionTypeInference(set_env).infer(
        ForOfExpression(
            quantifier=IntegerLiteral(value=1),
            string_set=SetExpression(elements=[StringIdentifier(name="$a")]),
            condition=None,
        ),
    )
    assert isinstance(fo, BooleanType)

    raw_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        raw_of.infer(OfExpression(quantifier="any", string_set=["$a", "$b"])),
        BooleanType,
    )
    assert raw_of.errors == []

    raw_for_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        raw_for_of.infer(ForOfExpression(quantifier="all", string_set="them", condition=None)),
        BooleanType,
    )
    assert raw_for_of.errors == []

    percent_for_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        percent_for_of.infer(
            ForOfExpression(
                quantifier=DoubleLiteral(value=0.5),
                string_set=Identifier(name="them"),
                condition=BooleanLiteral(value=True),
            )
        ),
        BooleanType,
    )
    assert any(
        "'for...of' quantifier must be string or integer" in e for e in percent_for_of.errors
    )

    bad_for_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        bad_for_of.infer(
            ForOfExpression(
                quantifier=SetExpression(elements=[]),
                string_set=Identifier(name="them"),
                condition=None,
            )
        ),
        BooleanType,
    )
    assert any("'for...of' quantifier must be string or integer" in e for e in bad_for_of.errors)


def test_expr_inference_handles_yarax_with_match_collections() -> None:
    ast = parse_yara_source("rule x { condition: with xs = [1]: match xs { _ => true } }")
    inf = ExpressionTypeInference(TypeEnvironment())

    assert ast.rules[0].condition is not None
    out = inf.infer(ast.rules[0].condition)

    assert isinstance(out, BooleanType)
    assert inf.errors == []


def test_expr_inference_reports_yarax_collection_mismatches() -> None:
    ast = parse_yara_source('rule x { condition: with xs = [1, "x"]: match xs { _ => true } }')
    inf = ExpressionTypeInference(TypeEnvironment())

    assert ast.rules[0].condition is not None
    out = inf.infer(ast.rules[0].condition)

    assert isinstance(out, BooleanType)
    assert any("Collection elements must have compatible types" in error for error in inf.errors)
