"""Additional real coverage for expression type inference."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.base import YaraFile
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
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modules import DictionaryAccess
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.ast.rules import Rule
from yaraast.parser.source import parse_yara_source
from yaraast.types._expr_inference import ExpressionTypeInference, _TypeBaseVisitor
from yaraast.types._registry import (
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    IntegerType,
    StringType,
    TypeEnvironment,
    UnknownType,
)
from yaraast.types.semantic_validator import SemanticValidator
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


def test_expr_inference_treats_extern_rule_references_as_boolean_conditions() -> None:
    reference = ExternRuleReference(rule_name="ExternalRule", namespace="ns")
    inference = ExpressionTypeInference(TypeEnvironment())

    assert isinstance(inference.visit(reference), BooleanType)

    ast = YaraFile(
        rules=[
            Rule(
                name="uses_external",
                condition=cast(Any, reference),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.errors == []


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

    nested_expr_inf = ExpressionTypeInference(env)
    assert isinstance(
        nested_expr_inf.infer(
            OfExpression(
                quantifier="any",
                string_set=[
                    BinaryExpression(
                        StringIdentifier("$missing"),
                        "and",
                        BooleanLiteral(value=True),
                    )
                ],
            )
        ),
        BooleanType,
    )
    assert "Undefined string: $missing" in nested_expr_inf.errors


def test_expr_inference_accepts_non_list_string_set_containers() -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    env.add_string("$b")

    of_inf = ExpressionTypeInference(env)
    assert isinstance(
        of_inf.infer(OfExpression(quantifier="any", string_set=("$a", "$b"))),
        BooleanType,
    )
    assert not any("'of' requires string set" in error for error in of_inf.errors)

    for_of_inf = ExpressionTypeInference(env)
    assert isinstance(
        for_of_inf.infer(
            ForOfExpression(
                quantifier="any",
                string_set=frozenset(("$a", "$b")),
                condition=BooleanLiteral(value=True),
            )
        ),
        BooleanType,
    )
    assert not any("'for...of' requires string set" in error for error in for_of_inf.errors)


def test_expr_inference_accepts_parenthesized_string_set_items() -> None:
    env = TypeEnvironment()
    env.add_string("$a")

    of_inf = ExpressionTypeInference(env)
    assert isinstance(
        of_inf.infer(
            OfExpression(
                quantifier="any",
                string_set=ParenthesesExpression(StringIdentifier("$a")),
            )
        ),
        BooleanType,
    )
    assert of_inf.errors == []

    for_of_inf = ExpressionTypeInference(env)
    assert isinstance(
        for_of_inf.infer(
            ForOfExpression(
                quantifier="any",
                string_set=ParenthesesExpression(StringIdentifier("$a")),
                condition=StringIdentifier("$"),
            )
        ),
        BooleanType,
    )
    assert for_of_inf.errors == []


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
            right=SetExpression(elements=[IntegerLiteral(value=1)]),
        ),
    )
    assert isinstance(right_bad, BooleanType)
    assert any("Right operand of 'and' must be truthy" in e for e in inf.errors)


def test_expr_inference_validates_module_function_argument_types() -> None:
    env = TypeEnvironment()
    env.add_module("math")
    inf = ExpressionTypeInference(env)

    out = inf.infer(FunctionCall(function="math.abs", arguments=[StringLiteral("bad")]))

    assert isinstance(out, IntegerType)
    assert any(
        "Argument 'x' to function 'abs' must be integer, got string" in e for e in inf.errors
    )

    valid_to_number = ExpressionTypeInference(env)
    to_number_out = valid_to_number.infer(
        FunctionCall(function="math.to_number", arguments=[BooleanLiteral(True)])
    )
    assert isinstance(to_number_out, IntegerType)
    assert valid_to_number.errors == []

    invalid_to_number = ExpressionTypeInference(env)
    invalid_to_number.infer(FunctionCall(function="math.to_number", arguments=[StringLiteral("1")]))
    assert any(
        "Argument 'b' to function 'to_number' must be boolean, got string" in e
        for e in invalid_to_number.errors
    )

    one_arg_to_string = ExpressionTypeInference(env)
    one_arg_to_string_out = one_arg_to_string.infer(
        FunctionCall(function="math.to_string", arguments=[IntegerLiteral(10)])
    )
    assert isinstance(one_arg_to_string_out, StringType)
    assert one_arg_to_string.errors == []

    two_arg_to_string = ExpressionTypeInference(env)
    two_arg_to_string_out = two_arg_to_string.infer(
        FunctionCall(
            function="math.to_string",
            arguments=[IntegerLiteral(10), IntegerLiteral(16)],
        )
    )
    assert isinstance(two_arg_to_string_out, StringType)
    assert two_arg_to_string.errors == []

    invalid_to_string = ExpressionTypeInference(env)
    invalid_to_string.infer(FunctionCall(function="math.to_string", arguments=[]))
    assert any(
        "Function 'to_string' expects 1 to 2 arguments, got 0" in e
        for e in invalid_to_string.errors
    )

    float_to_abs = ExpressionTypeInference(env)
    float_to_abs.infer(FunctionCall(function="math.abs", arguments=[DoubleLiteral(1.5)]))
    assert any(
        "Argument 'x' to function 'abs' must be integer, got double" in e
        for e in float_to_abs.errors
    )

    int_to_deviation_mean = ExpressionTypeInference(env)
    int_to_deviation_mean.infer(
        FunctionCall(
            function="math.deviation",
            arguments=[IntegerLiteral(0), IntegerLiteral(1), IntegerLiteral(97)],
        )
    )
    assert any(
        "Argument 'mean' to function 'deviation' must be double, got integer" in e
        for e in int_to_deviation_mean.errors
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


def test_expr_inference_accepts_extended_math_module_functions() -> None:
    env = TypeEnvironment()
    env.add_module("math")

    calls = [
        FunctionCall(function="math.mean", arguments=[IntegerLiteral(0), IntegerLiteral(1)]),
        FunctionCall(
            function="math.deviation",
            arguments=[IntegerLiteral(0), IntegerLiteral(1), DoubleLiteral(97.0)],
        ),
        FunctionCall(
            function="math.serial_correlation",
            arguments=[IntegerLiteral(0), IntegerLiteral(2)],
        ),
        FunctionCall(
            function="math.monte_carlo_pi",
            arguments=[IntegerLiteral(0), IntegerLiteral(6)],
        ),
    ]

    for call in calls:
        inf = ExpressionTypeInference(env)
        out = inf.infer(call)

        assert isinstance(out, DoubleType)
        assert inf.errors == []


def test_expr_inference_rejects_non_libyara_math_functions() -> None:
    env = TypeEnvironment()
    env.add_module("math")
    inf = ExpressionTypeInference(env)

    out = inf.infer(FunctionCall(function="math.log", arguments=[DoubleLiteral(1.0)]))

    assert isinstance(out, UnknownType)
    assert "Module 'math' has no function 'log'" in inf.errors


def test_expr_inference_accepts_known_optional_module_arguments() -> None:
    env = TypeEnvironment()
    env.add_module("pe")
    inf = ExpressionTypeInference(env)

    out = inf.infer(FunctionCall(function="pe.imports", arguments=[StringLiteral("kernel32.dll")]))

    assert isinstance(out, BooleanType)
    assert inf.errors == []


def test_expr_inference_treats_pe_predicates_as_functions_not_attributes() -> None:
    env = TypeEnvironment()
    env.add_module("pe")
    inf = ExpressionTypeInference(env)

    predicate_out = inf.infer(FunctionCall(function="pe.is_dll", arguments=[]))
    predicate_attribute_out = inf.infer(MemberAccess(object=Identifier("pe"), member="is_dll"))
    imports_attribute_out = inf.infer(MemberAccess(object=Identifier("pe"), member="imports"))
    exports_attribute_out = inf.infer(MemberAccess(object=Identifier("pe"), member="exports"))

    assert isinstance(predicate_out, BooleanType)
    assert isinstance(predicate_attribute_out, UnknownType)
    assert isinstance(imports_attribute_out, UnknownType)
    assert isinstance(exports_attribute_out, UnknownType)
    assert "Module 'pe' has no attribute 'is_dll'" in inf.errors
    assert "Module 'pe' has no attribute 'imports'" in inf.errors
    assert "Module 'pe' has no attribute 'exports'" in inf.errors


def test_expr_inference_member_access_prefers_module_over_same_named_rule() -> None:
    env = TypeEnvironment()
    env.add_module("pe")
    env.add_rule("pe")
    inf = ExpressionTypeInference(env)

    out = inf.infer(MemberAccess(object=Identifier("pe"), member="number_of_sections"))

    assert isinstance(out, IntegerType)
    assert inf.errors == []


def test_expr_inference_treats_time_now_as_function_not_attribute() -> None:
    env = TypeEnvironment()
    env.add_module("time")
    inf = ExpressionTypeInference(env)

    call_out = inf.infer(FunctionCall(function="time.now", arguments=[]))
    attr_out = inf.infer(MemberAccess(object=Identifier("time"), member="now"))

    assert isinstance(call_out, IntegerType)
    assert isinstance(attr_out, UnknownType)
    assert "Module 'time' has no attribute 'now'" in inf.errors


def test_expr_inference_treats_dotnet_assembly_as_struct_not_dictionary() -> None:
    env = TypeEnvironment()
    env.add_module("dotnet")
    inf = ExpressionTypeInference(env)
    assembly = MemberAccess(object=Identifier("dotnet"), member="assembly")
    version = MemberAccess(object=assembly, member="version")

    name_out = inf.infer(MemberAccess(object=assembly, member="name"))
    culture_out = inf.infer(MemberAccess(object=assembly, member="culture"))
    major_out = inf.infer(MemberAccess(object=version, member="major"))
    minor_out = inf.infer(MemberAccess(object=version, member="minor"))
    dictionary_out = inf.infer(DictionaryAccess(object=assembly, key="name"))

    assert isinstance(name_out, StringType)
    assert isinstance(culture_out, StringType)
    assert isinstance(major_out, IntegerType)
    assert isinstance(minor_out, IntegerType)
    assert isinstance(dictionary_out, UnknownType)
    assert any("Cannot access dictionary on non-dict type" in error for error in inf.errors)


def test_expr_inference_treats_dotnet_collections_as_arrays_of_structs() -> None:
    env = TypeEnvironment()
    env.add_module("dotnet")
    inf = ExpressionTypeInference(env)
    first_resource = ArrayAccess(
        array=MemberAccess(object=Identifier("dotnet"), member="resources"),
        index=IntegerLiteral(0),
    )
    first_stream = ArrayAccess(
        array=MemberAccess(object=Identifier("dotnet"), member="streams"),
        index=IntegerLiteral(0),
    )

    resource_name = inf.infer(MemberAccess(object=first_resource, member="name"))
    resource_offset = inf.infer(MemberAccess(object=first_resource, member="offset"))
    resource_length = inf.infer(MemberAccess(object=first_resource, member="length"))
    stream_name = inf.infer(MemberAccess(object=first_stream, member="name"))
    stream_offset = inf.infer(MemberAccess(object=first_stream, member="offset"))
    stream_size = inf.infer(MemberAccess(object=first_stream, member="size"))
    resource_dictionary = inf.infer(DictionaryAccess(object=first_resource, key="name"))

    assert isinstance(resource_name, StringType)
    assert isinstance(resource_offset, IntegerType)
    assert isinstance(resource_length, IntegerType)
    assert isinstance(stream_name, StringType)
    assert isinstance(stream_offset, IntegerType)
    assert isinstance(stream_size, IntegerType)
    assert isinstance(resource_dictionary, UnknownType)
    assert any("Cannot access dictionary on non-dict type" in error for error in inf.errors)


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


def test_expr_inference_for_variable_shadows_same_named_rule() -> None:
    env = TypeEnvironment()
    env.add_rule("item")
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        ForExpression(
            quantifier="any",
            variable="item",
            iterable=RangeExpression(
                low=IntegerLiteral(value=1),
                high=IntegerLiteral(value=2),
            ),
            body=BinaryExpression(
                left=Identifier(name="item"),
                operator="==",
                right=IntegerLiteral(value=1),
            ),
        )
    )

    assert isinstance(out, BooleanType)
    assert inf.errors == []


def test_expr_inference_flattens_collection_spreads() -> None:
    env = TypeEnvironment()
    env.define("tail", ArrayType(IntegerType()))
    env.define("rest", DictionaryType(StringType(), IntegerType()))

    list_inf = ExpressionTypeInference(env)
    list_type = list_inf.infer(
        ListExpression(
            elements=[
                IntegerLiteral(value=1),
                SpreadOperator(expression=Identifier(name="tail")),
            ],
        )
    )

    assert isinstance(list_type, ArrayType)
    assert isinstance(list_type.element_type, IntegerType)
    assert list_inf.errors == []

    dict_inf = ExpressionTypeInference(env)
    dict_type = dict_inf.infer(
        DictExpression(
            items=[
                DictItem(key=StringLiteral(value="a"), value=IntegerLiteral(value=1)),
                DictItem(
                    key=StringLiteral(value="__spread__"),
                    value=SpreadOperator(
                        expression=Identifier(name="rest"),
                        is_dict=True,
                    ),
                ),
            ],
        )
    )

    assert isinstance(dict_type, DictionaryType)
    assert isinstance(dict_type.key_type, StringType)
    assert isinstance(dict_type.value_type, IntegerType)
    assert dict_inf.errors == []


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
