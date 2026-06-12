"""Additional coverage for semantic_validator module convenience paths."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
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
    RegexLiteral,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.rules import Import, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.parser import Parser
from yaraast.types.semantic_validator import (
    SemanticValidator,
    check_function_calls,
    check_string_uniqueness,
    validate_yara_file,
    validate_yara_rule,
)
from yaraast.types.type_system import TypeEnvironment, TypeValidator
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    LambdaExpression,
    ListExpression,
    PatternMatch,
    WithDeclaration,
    WithStatement,
)


def _rule(name: str = "r", with_condition: bool = True) -> Rule:
    return Rule(
        name=name,
        strings=[PlainString(identifier="$a", value="x"), PlainString(identifier="$a", value="y")],
        condition=Identifier("true") if with_condition else None,
    )


def test_validate_rule_with_and_without_env_and_condition() -> None:
    validator = SemanticValidator()

    r1 = _rule(with_condition=True)
    res1 = validator.validate_rule(r1)
    assert res1.errors  # duplicate string id

    env = TypeEnvironment()
    env.add_module("pe")
    r2 = _rule(with_condition=False)
    res2 = validator.validate_rule(r2, env)
    assert res2.errors  # duplicate id still caught


def test_validate_rule_detects_undefined_string_references() -> None:
    rule = Rule(name="missing_string", strings=[], condition=StringIdentifier("$missing"))

    result = SemanticValidator().validate_rule(rule)

    assert result.is_valid is False
    assert any("Undefined string '$missing'" in error.message for error in result.errors)


@pytest.mark.parametrize("identifier", ["$a*", "$"])
def test_validate_rule_rejects_invalid_string_identifiers_without_aborting(
    identifier: str,
) -> None:
    rule = Rule(
        name="invalid_string_identifier",
        strings=[PlainString(identifier=identifier, value="test")],
        condition=BooleanLiteral(True),
    )

    result = SemanticValidator().validate_rule(rule)

    assert result.is_valid is False
    assert any("Invalid string reference" in error.message for error in result.errors)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (BooleanLiteral(cast(Any, object())), "Boolean literal value must be a boolean"),
        (IntegerLiteral(cast(Any, True)), "Integer literal value must be an integer"),
        (IntegerLiteral(cast(Any, object())), "Integer literal value must be an integer"),
        (DoubleLiteral(cast(Any, object())), "Double literal value must be numeric"),
        (StringLiteral(cast(Any, object())), "String literal value must be a string"),
        (RegexLiteral(cast(Any, object())), "Regex literal pattern must be a string"),
        (RegexLiteral("abc", cast(Any, object())), "Regex literal modifiers must be a string"),
        (Identifier(cast(Any, object())), "Identifier name must be a string"),
    ],
)
def test_semantic_validator_rejects_invalid_literal_scalars(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule("invalid_literal", condition=condition)])

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(error.message == message for error in result.errors)


@pytest.mark.parametrize("name", ["any", "all", "none"])
def test_semantic_validator_rejects_quantifier_keywords_as_plain_identifiers(
    name: str,
) -> None:
    ast = YaraFile(rules=[Rule("invalid_keyword_identifier", condition=Identifier(name))])

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(f"Invalid identifier identifier: {name}" in error.message for error in result.errors)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            BinaryExpression(cast(Any, object()), "and", BooleanLiteral(True)),
            "Binary expression left operand must be Expression",
        ),
        (
            BinaryExpression(BooleanLiteral(True), "and", cast(Any, object())),
            "Binary expression right operand must be Expression",
        ),
        (
            UnaryExpression("-", cast(Any, object())),
            "Unary expression operand must be Expression",
        ),
        (
            ParenthesesExpression(cast(Any, object())),
            "Parenthesized expression must be Expression",
        ),
        (
            SetExpression(cast(Any, object())),
            "Set expression elements must be a sequence",
        ),
        (
            SetExpression([cast(Any, object())]),
            "Set expression elements item must be Expression",
        ),
        (
            RangeExpression(cast(Any, object()), IntegerLiteral(1)),
            "Range low bound must be Expression",
        ),
        (
            RangeExpression(IntegerLiteral(1), cast(Any, object())),
            "Range high bound must be Expression",
        ),
        (
            ArrayAccess(cast(Any, object()), IntegerLiteral(0)),
            "Array access target must be Expression",
        ),
        (
            ArrayAccess(Identifier("items"), cast(Any, object())),
            "Array access index must be Expression",
        ),
        (
            MemberAccess(cast(Any, object()), "field"),
            "Member access object must be Expression",
        ),
        (
            ForExpression(
                "any",
                "i",
                cast(Any, object()),
                BooleanLiteral(True),
            ),
            "For-expression iterable must be Expression",
        ),
        (
            ForExpression(
                "any",
                "i",
                RangeExpression(IntegerLiteral(0), IntegerLiteral(1)),
                cast(Any, object()),
            ),
            "For-expression body must be Expression",
        ),
        (
            ForOfExpression("any", "$a", cast(Any, object())),
            "For-of condition must be Expression",
        ),
        (
            AtExpression("$a", cast(Any, object())),
            "At-expression offset must be Expression",
        ),
        (
            InExpression("$a", cast(Any, object())),
            "In-expression range must be Expression",
        ),
    ],
)
def test_semantic_validator_reports_invalid_expression_children(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule("invalid_child", condition=condition)])

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(error.message == message for error in result.errors)


def test_semantic_validator_checks_function_calls_inside_at_subject() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                "unknown_at_subject_function",
                condition=AtExpression(FunctionCall("unknown_func", []), IntegerLiteral(0)),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any("Unknown function 'unknown_func'" in warning.message for warning in result.warnings)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            WithStatement(cast(Any, object()), BooleanLiteral(True)),
            "With-statement declarations must be a sequence",
        ),
        (
            WithStatement([cast(Any, object())], BooleanLiteral(True)),
            "With-statement declarations item must be WithDeclaration",
        ),
        (
            DictExpression([cast(Any, object())]),
            "Dict expression items item must be DictItem",
        ),
        (
            PatternMatch(IntegerLiteral(1), [cast(Any, object())]),
            "Pattern match cases item must be MatchCase",
        ),
    ],
)
def test_semantic_validator_reports_invalid_yarax_collection_items(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule("invalid_yarax_collection", condition=condition)])

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(error.message == message for error in result.errors)


@pytest.mark.parametrize(
    ("expression", "message"),
    [
        (
            BinaryExpression(cast(Any, object()), "and", BooleanLiteral(True)),
            "Binary expression left operand must be Expression",
        ),
        (
            SetExpression(cast(Any, object())),
            "Set expression elements must be a sequence",
        ),
    ],
)
def test_validate_expression_reports_invalid_child_structure(
    expression: Any,
    message: str,
) -> None:
    result = SemanticValidator().validate_expression(expression)

    assert result.is_valid is False
    assert any(error.message == message for error in result.errors)


@pytest.mark.parametrize(
    "expression",
    [
        BinaryExpression(cast(Any, object()), "and", BooleanLiteral(True)),
        SetExpression(cast(Any, object())),
    ],
)
def test_type_validator_validate_expression_reports_invalid_child_structure(
    expression: Any,
) -> None:
    expr_type, errors = TypeValidator.validate_expression(expression)

    assert str(expr_type) == "unknown"
    assert errors


def test_validate_rule_detects_undefined_strings_in_raw_string_sets() -> None:
    rules = [
        Rule(
            name="missing_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=OfExpression("any", ["$a", "$missing"]),
        ),
        Rule(
            name="missing_for_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=ForOfExpression("any", ["$a", "$missing"], BooleanLiteral(True)),
        ),
        Rule(
            name="missing_set_expression",
            strings=[PlainString(identifier="$a", value="x")],
            condition=OfExpression(
                "any",
                SetExpression([StringLiteral("$a"), StringLiteral("$missing")]),
            ),
        ),
    ]

    result = SemanticValidator().validate(YaraFile(rules=rules))
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(
        "Undefined string '$missing' in rule 'missing_of'" in message for message in messages
    )
    assert any(
        "Undefined string '$missing' in rule 'missing_for_of'" in message for message in messages
    )
    assert any(
        "Undefined string '$missing' in rule 'missing_set_expression'" in message
        for message in messages
    )


def test_validate_rule_accepts_parenthesized_string_set_item() -> None:
    rules = [
        Rule(
            name="parenthesized_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=OfExpression("any", ParenthesesExpression(StringIdentifier("$a"))),
        ),
        Rule(
            name="parenthesized_for_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=ForOfExpression(
                "any",
                ParenthesesExpression(StringIdentifier("$a")),
                StringIdentifier("$"),
            ),
        ),
    ]

    result = SemanticValidator().validate(YaraFile(rules=rules))

    assert result.is_valid is True
    assert result.errors == []


def test_validate_rule_accepts_rule_wildcard_of_expression() -> None:
    ast = Parser().parse("""
        rule a1 { condition: true }
        rule a2 { condition: true }
        rule b { condition: any of (a*) }
        """)

    result = SemanticValidator().validate(ast)

    assert result.is_valid is True
    assert result.errors == []


def test_validate_rule_wildcard_does_not_report_string_pattern_error() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="b",
                condition=OfExpression("any", ParenthesesExpression(StringWildcard("a*"))),
            ),
        ]
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any("Undefined rule pattern: a*" in message for message in messages)
    assert not any("Undefined string pattern '$a*'" in message for message in messages)


def test_validate_rule_rejects_rule_wildcards_in_for_of_string_sets() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="consumer",
                condition=ForOfExpression(
                    "any",
                    StringWildcard("for*"),
                    BooleanLiteral(True),
                ),
            ),
        ],
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any("'for...of' requires string set" in message for message in messages)


def test_validate_rule_rejects_invalid_rule_wildcard_prefix() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="format_rule", condition=BooleanLiteral(True)),
            Rule(name="consumer", condition=OfExpression("any", StringWildcard("for*"))),
        ]
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any("Invalid rule pattern identifier: for" in message for message in messages)


def test_validate_rule_detects_invalid_condition_type() -> None:
    rule = Rule(
        name="bad_type",
        strings=[],
        condition=SetExpression(elements=[IntegerLiteral(value=1)]),
    )

    result = SemanticValidator().validate_rule(rule)

    assert result.is_valid is False
    assert any("Rule condition must be boolean" in error.message for error in result.errors)


def test_validate_file_rejects_duplicate_rule_names() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="dup", condition=BooleanLiteral(True)),
            Rule(name="dup", condition=BooleanLiteral(True)),
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any("Duplicate rule identifier: dup" in error.message for error in result.errors)


@pytest.mark.parametrize("rule_name", ["bad-name", "rule*", "*", "for"])
def test_validate_file_rejects_invalid_rule_names(rule_name: str) -> None:
    ast = YaraFile(rules=[Rule(name=rule_name, condition=BooleanLiteral(True))])

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(f"Invalid rule identifier: {rule_name}" in error.message for error in result.errors)


@pytest.mark.parametrize(
    "import_node",
    [
        Import("pe", alias="bad-name"),
        Import("pe", alias="for"),
        Import("   "),
    ],
)
def test_validate_file_rejects_invalid_import_fields_without_aborting(
    import_node: Import,
) -> None:
    ast = YaraFile(
        imports=[import_node],
        rules=[Rule(name="ok_rule", condition=BooleanLiteral(True))],
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert result.errors


def test_validate_file_rejects_duplicate_rule_tags() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="tagged",
                tags=[Tag("alpha"), Tag("alpha")],
                condition=BooleanLiteral(True),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(
        "Duplicate tag identifier 'alpha' in rule 'tagged'" in error.message
        for error in result.errors
    )


def test_validate_file_rejects_forward_rule_reference() -> None:
    ast = Parser().parse("""
        rule first {
            condition:
                second
        }

        rule second {
            condition:
                true
        }
        """)

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any("Rule condition must be boolean" in error.message for error in result.errors)


def test_validate_file_accepts_self_and_previous_rule_references() -> None:
    ast = Parser().parse("""
        rule first {
            condition:
                first
        }

        rule second {
            condition:
                first
        }
        """)

    result = SemanticValidator().validate(ast)

    assert result.is_valid is True
    assert result.errors == []


def test_validate_rule_normalizes_direct_ast_string_identifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="direct_string",
                strings=[PlainString(identifier="a", value="x")],
                condition=StringIdentifier("$a"),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is True
    assert result.errors == []


def test_validate_file_rejects_unknown_imported_module() -> None:
    ast = Parser().parse("""
        import "nosuch"

        rule imports_unknown {
            condition:
                true
        }
        """)

    result = SemanticValidator().validate(ast)
    is_valid, type_errors = TypeValidator.validate(ast)

    assert result.is_valid is False
    assert any("Unknown module: nosuch" in error.message for error in result.errors)
    assert is_valid is False
    assert "Unknown module: nosuch" in type_errors


def test_validate_expression_and_convenience_functions() -> None:
    validator = SemanticValidator()
    expr = FunctionCall(function="pe.imphash", arguments=[])

    # env None branch
    res_expr = validator.validate_expression(expr)
    assert res_expr.errors

    rule = _rule()
    yf = YaraFile(rules=[rule])

    full = validate_yara_file(yf)
    assert full.errors

    single = validate_yara_rule(rule)
    assert single.errors

    uniq_errors = check_string_uniqueness(rule)
    assert uniq_errors

    fn_errors = check_function_calls(expr, TypeEnvironment())
    assert fn_errors


def test_validate_expression_detects_type_errors() -> None:
    expr = BinaryExpression(
        left=IntegerLiteral(value=1),
        operator="+",
        right=StringLiteral(value="x"),
    )

    result = SemanticValidator().validate_expression(expr)

    assert result.is_valid is False
    assert any("Right operand of '+' must be numeric" in error.message for error in result.errors)


@pytest.mark.parametrize("variable", ["bad-name", "1bad", "for"])
def test_validate_expression_rejects_invalid_for_expression_variable_identifiers(
    variable: str,
) -> None:
    expr = ForExpression(
        quantifier="any",
        variable=variable,
        iterable=SetExpression([IntegerLiteral(value=1)]),
        body=BooleanLiteral(value=True),
    )

    result = SemanticValidator().validate_expression(expr)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(f"Invalid loop variable identifier: {variable}" in message for message in messages)


@pytest.mark.parametrize("variable", ["as", "include"])
def test_validate_expression_allows_contextual_keyword_for_expression_variables(
    variable: str,
) -> None:
    expr = ForExpression(
        quantifier="any",
        variable=variable,
        iterable=SetExpression([IntegerLiteral(value=1)]),
        body=BinaryExpression(Identifier(variable), ">", IntegerLiteral(value=0)),
    )

    result = SemanticValidator().validate_expression(expr)
    messages = [error.message for error in result.errors]

    assert not any(
        f"Invalid loop variable identifier: {variable}" in message for message in messages
    )
    assert not any(f"Invalid identifier identifier: {variable}" in message for message in messages)


@pytest.mark.parametrize(
    ("expr", "variable"),
    [
        (
            WithStatement(
                declarations=[WithDeclaration("bad-name", IntegerLiteral(1))],
                body=BooleanLiteral(True),
            ),
            "bad-name",
        ),
        (
            ArrayComprehension(
                expression=IntegerLiteral(1),
                variable="1bad",
                iterable=ListExpression([IntegerLiteral(1)]),
            ),
            "1bad",
        ),
        (
            DictComprehension(
                key_expression=StringLiteral("k"),
                value_expression=IntegerLiteral(1),
                key_variable="for",
                iterable=ListExpression([IntegerLiteral(1)]),
            ),
            "for",
        ),
        (
            DictComprehension(
                key_expression=StringLiteral("k"),
                value_expression=IntegerLiteral(1),
                key_variable="k",
                value_variable="bad-name",
                iterable=ListExpression([IntegerLiteral(1)]),
            ),
            "bad-name",
        ),
        (LambdaExpression(parameters=["1bad"], body=BooleanLiteral(True)), "1bad"),
    ],
)
def test_validate_expression_rejects_invalid_yarax_local_variable_identifiers(
    expr: Any,
    variable: str,
) -> None:
    result = SemanticValidator().validate_expression(expr)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(f"Invalid local variable identifier: {variable}" in message for message in messages)


def test_semantic_validator_rejects_non_mapping_externals() -> None:
    ast = YaraFile(rules=[Rule(name="externals", condition=BooleanLiteral(True))])
    rule = ast.rules[0]

    with pytest.raises(TypeError, match="SemanticValidator externals must be a mapping"):
        SemanticValidator(externals=cast(Any, []))

    validator = SemanticValidator()

    with pytest.raises(TypeError, match="SemanticValidator externals must be a mapping"):
        validator.validate(ast, externals=cast(Any, []))

    with pytest.raises(TypeError, match="SemanticValidator externals must be a mapping"):
        validator.validate_rule(rule, externals=cast(Any, []))

    with pytest.raises(TypeError, match="SemanticValidator externals must be a mapping"):
        validator.validate_expression(BooleanLiteral(True), externals=cast(Any, []))


@pytest.mark.parametrize("externals", [{cast(Any, 1): 1}, {cast(Any, True): 1}])
def test_semantic_validator_rejects_non_string_external_names(externals: dict[Any, object]) -> None:
    ast = YaraFile(rules=[Rule(name="externals", condition=BooleanLiteral(True))])
    rule = ast.rules[0]

    with pytest.raises(TypeError, match="SemanticValidator external names must be strings"):
        SemanticValidator(externals=cast(Any, externals))

    validator = SemanticValidator()

    with pytest.raises(TypeError, match="SemanticValidator external names must be strings"):
        validator.validate(ast, externals=cast(Any, externals))

    with pytest.raises(TypeError, match="SemanticValidator external names must be strings"):
        validator.validate_rule(rule, externals=cast(Any, externals))

    with pytest.raises(TypeError, match="SemanticValidator external names must be strings"):
        validator.validate_expression(BooleanLiteral(True), externals=cast(Any, externals))


@pytest.mark.parametrize("externals", [{"": 1}, {"   ": 1}])
def test_semantic_validator_rejects_empty_external_names(externals: dict[str, object]) -> None:
    ast = YaraFile(rules=[Rule(name="externals", condition=BooleanLiteral(True))])
    rule = ast.rules[0]

    with pytest.raises(ValueError, match="SemanticValidator external names must not be empty"):
        SemanticValidator(externals=externals)

    validator = SemanticValidator()

    with pytest.raises(ValueError, match="SemanticValidator external names must not be empty"):
        validator.validate(ast, externals=externals)

    with pytest.raises(ValueError, match="SemanticValidator external names must not be empty"):
        validator.validate_rule(rule, externals=externals)

    with pytest.raises(ValueError, match="SemanticValidator external names must not be empty"):
        validator.validate_expression(BooleanLiteral(True), externals=externals)


@pytest.mark.parametrize("externals", [{"x": b"bytes"}, {"x": None}, {"x": object()}])
def test_semantic_validator_rejects_unsupported_external_values(
    externals: dict[str, object],
) -> None:
    ast = YaraFile(rules=[Rule(name="externals", condition=BooleanLiteral(True))])
    rule = ast.rules[0]

    with pytest.raises(
        TypeError,
        match="SemanticValidator external values must be integer, float, boolean, or string",
    ):
        SemanticValidator(externals=externals)

    validator = SemanticValidator()

    with pytest.raises(
        TypeError,
        match="SemanticValidator external values must be integer, float, boolean, or string",
    ):
        validator.validate(ast, externals=externals)

    with pytest.raises(
        TypeError,
        match="SemanticValidator external values must be integer, float, boolean, or string",
    ):
        validator.validate_rule(rule, externals=externals)

    with pytest.raises(
        TypeError,
        match="SemanticValidator external values must be integer, float, boolean, or string",
    ):
        validator.validate_expression(BooleanLiteral(True), externals=externals)


def test_semantic_validator_accepts_supported_external_values() -> None:
    ast = YaraFile(rules=[Rule(name="externals", condition=BooleanLiteral(True))])
    externals = {"i": 1, "f": 1.5, "b": True, "s": "text"}

    assert SemanticValidator(externals=externals).validate(ast).is_valid is True


@pytest.mark.parametrize("externals", [{"bad-name": 1}, {"1bad": 1}, {"for": 1}])
def test_semantic_validator_rejects_invalid_external_names(
    externals: dict[str, object],
) -> None:
    ast = YaraFile(rules=[Rule(name="externals", condition=BooleanLiteral(True))])
    rule = ast.rules[0]

    with pytest.raises(ValueError, match="SemanticValidator external names must be valid"):
        SemanticValidator(externals=externals)

    validator = SemanticValidator()

    with pytest.raises(ValueError, match="SemanticValidator external names must be valid"):
        validator.validate(ast, externals=externals)

    with pytest.raises(ValueError, match="SemanticValidator external names must be valid"):
        validator.validate_rule(rule, externals=externals)

    with pytest.raises(ValueError, match="SemanticValidator external names must be valid"):
        validator.validate_expression(BooleanLiteral(True), externals=externals)


@pytest.mark.parametrize(
    "condition",
    [
        "math.in_range(2.0, 1.0, 3.0)",
        "math.count(0x00) >= 0",
        "math.count(0x00, 0, filesize) >= 0",
        "math.percentage(0x00) >= 0.0",
        "math.percentage(0x00, 0, filesize) >= 0.0",
        "math.mode() >= 0",
        "math.mode(0, filesize) >= 0",
    ],
)
def test_semantic_validator_accepts_libyara_math_overloads(condition: str) -> None:
    """libyara accepts these math overloads; the validator must not flag them."""
    source = f'import "math"\nrule r {{ condition: {condition} }}'
    ast = Parser(source).parse()
    result = SemanticValidator().validate(ast)
    assert result.is_valid is True, [error.message for error in result.errors]


@pytest.mark.parametrize(
    "condition",
    [
        "math.in_range(2, 1, 3)",
        "math.in_range(1.0, 2.0)",
        "math.count(0, 1) >= 0",
        "math.percentage(0, 1) >= 0.0",
        "math.mode(0) >= 0",
    ],
)
def test_semantic_validator_rejects_invalid_math_overloads(condition: str) -> None:
    """libyara rejects these math overloads; the validator must flag them too."""
    source = f'import "math"\nrule r {{ condition: {condition} }}'
    ast = Parser(source).parse()
    result = SemanticValidator().validate(ast)
    assert result.is_valid is False
