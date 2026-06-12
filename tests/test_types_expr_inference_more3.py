"""Additional real coverage for expression type inference."""

from __future__ import annotations

from typing import Any, cast

import pytest

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
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modules import DictionaryAccess, ModuleReference
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
    FloatType,
    IntegerType,
    StringIdentifierType,
    StringType,
    StructType,
    TypeEnvironment,
    UnknownType,
)
from yaraast.types.semantic_validator import SemanticValidator
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
    TupleIndexing,
    WithDeclaration,
    WithStatement,
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


@pytest.mark.parametrize("name", ["bad-name", "1bad", "for", ""])
def test_expr_inference_rejects_invalid_identifier_names_before_environment_lookup(
    name: str,
) -> None:
    env = TypeEnvironment()
    if name:
        env.scopes[-1][name] = IntegerType()
    inf = ExpressionTypeInference(env)

    out = inf.infer(Identifier(name))

    assert isinstance(out, UnknownType)
    assert inf.errors


@pytest.mark.parametrize("name", ["any", "all", "none"])
def test_expr_inference_rejects_quantifier_keywords_as_plain_identifiers(name: str) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(Identifier(name))

    assert isinstance(out, UnknownType)
    assert any(f"Invalid identifier identifier: {name}" in error for error in inf.errors)


@pytest.mark.parametrize("name", ["any", "all", "none"])
def test_expr_inference_allows_identifier_quantifier_keywords_in_of_expression(
    name: str,
) -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    inf = ExpressionTypeInference(env)

    out = inf.infer(OfExpression(Identifier(name), Identifier("them")))

    assert isinstance(out, BooleanType)
    assert not inf.errors


def test_expr_inference_treats_identifier_string_reference_as_string_identifier() -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    inf = ExpressionTypeInference(env)

    out = inf.infer(Identifier("$a"))

    assert isinstance(out, StringIdentifierType)
    assert inf.errors == []


@pytest.mark.parametrize("function", ["bad-name", "pe..imports", "for", ""])
def test_expr_inference_rejects_invalid_function_names(function: str) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(FunctionCall(function=function, arguments=[IntegerLiteral(0)]))

    assert isinstance(out, UnknownType)
    assert inf.errors


@pytest.mark.parametrize("module", ["bad-name", "for", "", cast(Any, 123)])
def test_expr_inference_rejects_invalid_module_references(module: Any) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(ModuleReference(module))

    assert isinstance(out, UnknownType)
    assert inf.errors


@pytest.mark.parametrize(
    "expression",
    [
        AtExpression(string_id="$*", offset=IntegerLiteral(value=0)),
        InExpression(
            subject="$*",
            range=RangeExpression(IntegerLiteral(value=0), IntegerLiteral(value=1)),
        ),
    ],
)
def test_expr_inference_rejects_wildcard_string_references_in_concrete_contexts(
    expression: Any,
) -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    inf = ExpressionTypeInference(env)

    out = inf.infer(expression)

    assert isinstance(out, BooleanType)
    assert "Invalid string reference '$*'" in inf.errors


@pytest.mark.parametrize(
    "expression",
    [
        OfExpression(quantifier=-1, string_set=Identifier(name="them")),
        OfExpression(quantifier="", string_set=Identifier(name="them")),
        OfExpression(quantifier="true", string_set=Identifier(name="them")),
        OfExpression(quantifier="bad-key", string_set=Identifier(name="them")),
        OfExpression(quantifier=StringLiteral(value="-1"), string_set=Identifier(name="them")),
        ForOfExpression(
            quantifier=-1,
            string_set=Identifier(name="them"),
            condition=BooleanLiteral(value=True),
        ),
        ForOfExpression(
            quantifier="",
            string_set=Identifier(name="them"),
            condition=BooleanLiteral(value=True),
        ),
        ForOfExpression(
            quantifier=DoubleLiteral(value=1.01),
            string_set=Identifier(name="them"),
            condition=BooleanLiteral(value=True),
        ),
    ],
)
def test_expr_inference_rejects_invalid_of_quantifier_values(expression: Any) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(expression)

    assert isinstance(out, BooleanType)
    assert inf.errors


@pytest.mark.parametrize("name", ["true", "false"])
def test_expr_inference_treats_boolean_keyword_identifiers_as_booleans(name: str) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(Identifier(name))

    assert isinstance(out, BooleanType)
    assert inf.errors == []


@pytest.mark.parametrize("name", ["$bad-name", "$*", "", cast(Any, 123)])
def test_expr_inference_rejects_invalid_string_identifiers_before_lookup(name: Any) -> None:
    env = TypeEnvironment()
    if isinstance(name, str) and name:
        env.scopes[-1][name] = StringIdentifierType()
    inf = ExpressionTypeInference(env)

    out = inf.infer(StringIdentifier(name))

    assert isinstance(out, UnknownType)
    assert inf.errors


@pytest.mark.parametrize("pattern", ["$bad-name*", "$", "", cast(Any, 123)])
def test_expr_inference_rejects_invalid_string_wildcards(pattern: Any) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(StringWildcard(pattern))

    assert isinstance(out, UnknownType)
    assert inf.errors


def test_expr_inference_rejects_rule_wildcards_in_for_of_string_sets() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        ForOfExpression(
            quantifier="any",
            string_set=StringWildcard("helper*"),
            condition=BooleanLiteral(True),
        )
    )

    assert isinstance(out, BooleanType)
    assert any("'for...of' requires string set" in error for error in inf.errors)


def test_expr_inference_reports_undefined_string_variants() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert isinstance(inf.infer(StringCount(string_id="missing")), UnknownType)
    assert isinstance(inf.infer(StringOffset(string_id="missing")), UnknownType)
    assert isinstance(inf.infer(StringLength(string_id="missing")), UnknownType)

    assert "Undefined string: $missing" in inf.errors[0]
    assert "Undefined string: $missing" in inf.errors[1]
    assert "Undefined string: $missing" in inf.errors[2]


def test_expr_inference_reports_embedded_string_reference_operators() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert isinstance(inf.infer(StringCount(string_id="#a")), UnknownType)
    assert isinstance(inf.infer(StringOffset(string_id="@a")), UnknownType)
    assert isinstance(inf.infer(StringLength(string_id="!a")), UnknownType)

    assert inf.errors == [
        "Invalid string reference '#a'",
        "Invalid string reference '@a'",
        "Invalid string reference '!a'",
    ]


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


def test_expr_inference_resolves_yarax_string_locals_in_string_sets() -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        WithStatement(
            declarations=[WithDeclaration("$x", StringLiteral("$a"))],
            body=OfExpression("any", SetExpression([StringIdentifier("$x")])),
        )
    )

    assert isinstance(out, BooleanType)
    assert "Undefined string: $x" not in inf.errors
    assert inf.errors == []


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


def test_expr_inference_accepts_bare_string_literal_string_set_items() -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    env.add_string("$api_call")

    cases = [
        OfExpression("any", SetExpression([StringLiteral("a")])),
        OfExpression("any", SetExpression([StringLiteral("api*")])),
        ForOfExpression(
            "any",
            SetExpression([StringLiteral("a")]),
            BooleanLiteral(value=True),
        ),
    ]

    for expression in cases:
        inf = ExpressionTypeInference(env)

        assert isinstance(inf.infer(expression), BooleanType)
        assert inf.errors == []


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

    for bad in (
        BinaryExpression(BooleanLiteral(value=True), "!=", IntegerLiteral(value=1)),
        BinaryExpression(IntegerLiteral(value=1), ">", BooleanLiteral(value=False)),
    ):
        out = inf.infer(bad)
        assert isinstance(out, BooleanType)
    assert any("Boolean operands cannot be used with '!=' comparisons" in e for e in inf.errors)
    assert any("Boolean operands cannot be used with '>' comparisons" in e for e in inf.errors)

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
        "Function 'deviation' does not accept argument types (integer, integer, integer)" in e
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
        FunctionCall(function="math.mean", arguments=[StringLiteral("abc")]),
        FunctionCall(
            function="math.deviation",
            arguments=[IntegerLiteral(0), IntegerLiteral(1), DoubleLiteral(97.0)],
        ),
        FunctionCall(
            function="math.deviation",
            arguments=[StringLiteral("abc"), DoubleLiteral(97.0)],
        ),
        FunctionCall(
            function="math.serial_correlation",
            arguments=[IntegerLiteral(0), IntegerLiteral(2)],
        ),
        FunctionCall(
            function="math.serial_correlation",
            arguments=[StringLiteral("abc")],
        ),
        FunctionCall(
            function="math.monte_carlo_pi",
            arguments=[IntegerLiteral(0), IntegerLiteral(6)],
        ),
        FunctionCall(
            function="math.count",
            arguments=[IntegerLiteral(97), IntegerLiteral(0), IntegerLiteral(3)],
        ),
        FunctionCall(
            function="math.percentage",
            arguments=[IntegerLiteral(97), IntegerLiteral(0), IntegerLiteral(3)],
        ),
        FunctionCall(function="math.mode", arguments=[IntegerLiteral(0), IntegerLiteral(3)]),
    ]

    for call in calls:
        inf = ExpressionTypeInference(env)
        out = inf.infer(call)

        if call.function in {"math.count", "math.mode"}:
            assert isinstance(out, IntegerType)
        else:
            assert isinstance(out, DoubleType)
        assert inf.errors == []


def test_expr_inference_rejects_non_libyara_math_functions() -> None:
    env = TypeEnvironment()
    env.add_module("math")
    inf = ExpressionTypeInference(env)

    out = inf.infer(FunctionCall(function="math.log", arguments=[DoubleLiteral(1.0)]))

    assert isinstance(out, UnknownType)
    assert "Module 'math' has no function 'log'" in inf.errors


@pytest.mark.parametrize("operator", ["+", "-", "*", "/"])
def test_expr_inference_float_arithmetic_returns_float(operator: str) -> None:
    env = TypeEnvironment()
    env.define("ratio", FloatType())

    left_first = ExpressionTypeInference(env)
    out_left = left_first.infer(
        BinaryExpression(
            left=Identifier(name="ratio"),
            operator=operator,
            right=IntegerLiteral(2),
        )
    )
    assert isinstance(out_left, FloatType)
    assert left_first.errors == []

    right_first = ExpressionTypeInference(env)
    out_right = right_first.infer(
        BinaryExpression(
            left=IntegerLiteral(2),
            operator=operator,
            right=Identifier(name="ratio"),
        )
    )
    assert isinstance(out_right, FloatType)
    assert right_first.errors == []


def test_expr_inference_accepts_known_optional_module_arguments() -> None:
    env = TypeEnvironment()
    env.add_module("pe")
    inf = ExpressionTypeInference(env)

    out = inf.infer(FunctionCall(function="pe.imports", arguments=[StringLiteral("kernel32.dll")]))

    assert isinstance(out, IntegerType)
    assert inf.errors == []


def test_expr_inference_treats_pe_predicates_as_functions_not_attributes() -> None:
    env = TypeEnvironment()
    env.add_module("pe")
    inf = ExpressionTypeInference(env)

    predicate_out = inf.infer(FunctionCall(function="pe.is_dll", arguments=[]))
    predicate_attribute_out = inf.infer(MemberAccess(object=Identifier("pe"), member="is_dll"))
    imports_attribute_out = inf.infer(MemberAccess(object=Identifier("pe"), member="imports"))
    exports_attribute_out = inf.infer(MemberAccess(object=Identifier("pe"), member="exports"))

    assert isinstance(predicate_out, IntegerType)
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


@pytest.mark.parametrize(
    ("member", "message"),
    [
        ("bad-name", "Invalid member identifier: bad-name"),
        ("1bad", "Invalid member identifier: 1bad"),
        ("for", "Invalid member identifier: for"),
        ("", "Member access member cannot be empty"),
    ],
)
def test_expr_inference_rejects_invalid_struct_member_identifiers(
    member: str,
    message: str,
) -> None:
    env = TypeEnvironment()
    env.define("obj", StructType(fields={member: IntegerType()}))
    inf = ExpressionTypeInference(env)

    out = inf.infer(MemberAccess(object=Identifier("obj"), member=member))

    assert isinstance(out, UnknownType)
    assert message in inf.errors


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


@pytest.mark.parametrize("variable", ["bad-name", "1bad", "for"])
def test_expr_inference_rejects_invalid_yarax_local_variable_identifiers(
    variable: str,
) -> None:
    cases = [
        WithStatement(
            declarations=[WithDeclaration(variable, IntegerLiteral(1))],
            body=BooleanLiteral(True),
        ),
        ArrayComprehension(
            expression=IntegerLiteral(1),
            variable=variable,
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        DictComprehension(
            key_expression=StringLiteral("k"),
            value_expression=IntegerLiteral(1),
            key_variable=variable,
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        DictComprehension(
            key_expression=StringLiteral("k"),
            value_expression=IntegerLiteral(1),
            key_variable="k",
            value_variable=variable,
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        LambdaExpression(parameters=[variable], body=BooleanLiteral(True)),
    ]

    for case in cases:
        inf = ExpressionTypeInference(TypeEnvironment())
        inf.infer(case)

        assert f"Invalid local variable identifier: {variable}" in inf.errors


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

    at_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        at_of.infer(
            AtExpression(
                string_id=OfExpression("all", Identifier("them")),
                offset=IntegerLiteral(value=0),
            )
        ),
        BooleanType,
    )
    assert at_of.errors == []

    assert isinstance(
        inf.infer(InExpression(subject="$a", range=IntegerLiteral(value=1))),
        BooleanType,
    )
    assert any("'in' expression requires range" in e for e in inf.errors)

    in_count_env = TypeEnvironment()
    in_count_env.add_string("$a")
    in_count = ExpressionTypeInference(in_count_env)
    assert isinstance(
        in_count.infer(
            InExpression(
                subject=StringCount("a"),
                range=RangeExpression(IntegerLiteral(value=0), IntegerLiteral(value=1)),
            )
        ),
        IntegerType,
    )
    assert in_count.errors == []

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

    zero_percent_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        zero_percent_of.infer(
            OfExpression(
                quantifier=DoubleLiteral(value=0.0),
                string_set=Identifier(name="them"),
            ),
        ),
        BooleanType,
    )
    assert any(
        "'of' percentage quantifier must be between 1 and 100" in e for e in zero_percent_of.errors
    )

    for percentage in (1.01,):
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


def test_expr_inference_rejects_raw_boolean_quantifiers() -> None:
    of_inf = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        of_inf.infer(OfExpression(quantifier=True, string_set=Identifier(name="them"))),
        BooleanType,
    )
    assert any("'of' quantifier must be string, integer, or percentage" in e for e in of_inf.errors)

    for_inf = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        for_inf.infer(
            ForExpression(
                quantifier=True,
                variable="i",
                iterable=SetExpression([IntegerLiteral(value=1)]),
                body=BooleanLiteral(value=True),
            )
        ),
        BooleanType,
    )
    assert any("'for' quantifier must be string or integer" in e for e in for_inf.errors)

    for_of_inf = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        for_of_inf.infer(
            ForOfExpression(
                quantifier=True,
                string_set=Identifier(name="them"),
                condition=BooleanLiteral(value=True),
            )
        ),
        BooleanType,
    )
    assert any("'for...of' quantifier must be" in e for e in for_of_inf.errors)


def test_expr_inference_allows_dynamic_percentage_of_quantifier() -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    inf = ExpressionTypeInference(env)

    out = inf.infer(
        OfExpression(
            quantifier=UnaryExpression("%", StringCount("a")),
            string_set=Identifier("them"),
        )
    )

    assert isinstance(out, BooleanType)
    assert not inf.errors


def test_expr_inference_rejects_static_zero_percentage_of_quantifier() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        OfExpression(
            quantifier=UnaryExpression("%", IntegerLiteral(0)),
            string_set=Identifier("them"),
        )
    )

    assert isinstance(out, BooleanType)
    assert any("'of' percentage quantifier must be between 1 and 100" in e for e in inf.errors)


def test_expr_inference_rejects_static_binary_percentage_of_quantifier_overflow() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        OfExpression(
            quantifier=UnaryExpression(
                "%",
                BinaryExpression(IntegerLiteral(51), "*", IntegerLiteral(2)),
            ),
            string_set=Identifier("them"),
        )
    )

    assert isinstance(out, BooleanType)
    assert any("'of' percentage quantifier must be between 1 and 100" in e for e in inf.errors)


def test_expr_inference_uses_signed_remainder_for_static_percentage_quantifier() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        OfExpression(
            quantifier=UnaryExpression(
                "%",
                BinaryExpression(
                    UnaryExpression("-", UnaryExpression("-", IntegerLiteral(25))),
                    "%",
                    UnaryExpression("~", IntegerLiteral(100)),
                ),
            ),
            string_set=Identifier("them"),
        )
    )

    assert isinstance(out, BooleanType)
    assert not inf.errors


def test_expr_inference_rejects_non_integer_static_percentage_expression() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        OfExpression(
            quantifier=UnaryExpression(
                "%",
                UnaryExpression("-", UnaryExpression("-", DoubleLiteral(1.2))),
            ),
            string_set=Identifier("them"),
        )
    )

    assert isinstance(out, BooleanType)
    assert any("'of' percentage quantifier must be an integer expression" in e for e in inf.errors)


def test_expr_inference_rejects_shifted_zero_percentage_quantifier() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        OfExpression(
            quantifier=UnaryExpression(
                "%",
                BinaryExpression(
                    BinaryExpression(
                        UnaryExpression("-", StringCount("a")),
                        ">>",
                        IntegerLiteral(50),
                    ),
                    ">>",
                    IntegerLiteral(101),
                ),
            ),
            string_set=Identifier("them"),
        )
    )

    assert isinstance(out, BooleanType)
    assert any("'of' percentage quantifier must be between 1 and 100" in e for e in inf.errors)


def test_expr_inference_rejects_invalid_for_expression_variable_names() -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        ForExpression(
            quantifier="any",
            variable=cast(Any, False),
            iterable=SetExpression([IntegerLiteral(value=1)]),
            body=BooleanLiteral(value=True),
        )
    )

    assert isinstance(out, BooleanType)
    assert "For-expression variable must be a string" in inf.errors


@pytest.mark.parametrize("variable", ["bad-name", "1bad", "for"])
def test_expr_inference_rejects_invalid_for_expression_variable_identifiers(
    variable: str,
) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        ForExpression(
            quantifier="any",
            variable=variable,
            iterable=SetExpression([IntegerLiteral(value=1)]),
            body=BooleanLiteral(value=True),
        )
    )

    assert isinstance(out, BooleanType)
    assert f"Invalid loop variable identifier: {variable}" in inf.errors


@pytest.mark.parametrize("variable", ["as", "include"])
def test_expr_inference_allows_contextual_keyword_for_expression_variables(variable: str) -> None:
    inf = ExpressionTypeInference(TypeEnvironment())

    out = inf.infer(
        ForExpression(
            quantifier="any",
            variable=variable,
            iterable=SetExpression([IntegerLiteral(value=1)]),
            body=BinaryExpression(Identifier(variable), ">", IntegerLiteral(value=0)),
        )
    )

    assert isinstance(out, BooleanType)
    assert f"Invalid loop variable identifier: {variable}" not in inf.errors
    assert f"Invalid identifier identifier: {variable}" not in inf.errors


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


def test_semantic_validator_accepts_for_expression_tuple_iterables() -> None:
    ast = parse_yara_source("""
        rule tuple_iterables {
            condition:
                for any i in (1, 2, 3) : (i == 2) and
                for any s in ("a", "b") : (s == "a")
        }
        """)

    result = SemanticValidator().validate(ast)

    assert result.is_valid
    assert result.errors == []


def test_semantic_validator_accepts_scalar_for_loop_conditions() -> None:
    ast = parse_yara_source("""
        rule scalar_loop_conditions {
            strings:
                $a = "a"
            condition:
                for any i in (1, 2) : (i) and
                for any j in (1, 2) : (1.0) and
                for any k in (1, 2) : ("x") and
                for any of them : (#) and
                for any of them : (@) and
                for any of them : (!)
        }
        """)

    result = SemanticValidator().validate(ast)

    assert result.is_valid
    assert result.errors == []


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
    assert percent_for_of.errors == []

    zero_percent_for_of = ExpressionTypeInference(TypeEnvironment())
    assert isinstance(
        zero_percent_for_of.infer(
            ForOfExpression(
                quantifier=DoubleLiteral(value=0.0),
                string_set=Identifier(name="them"),
                condition=BooleanLiteral(value=True),
            )
        ),
        BooleanType,
    )
    assert any(
        "'for...of' percentage quantifier must be between 1 and 100" in e
        for e in zero_percent_for_of.errors
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
    assert any("'for...of' quantifier must be" in e for e in bad_for_of.errors)


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
