"""Protobuf roundtrip tests for YARA-X AST nodes."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, Identifier, IntegerLiteral
from yaraast.ast.rules import Rule
from yaraast.errors import SerializationError
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
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


def test_protobuf_serializer_preserves_yarax_expression_roundtrip() -> None:
    condition = WithStatement(
        declarations=[
            WithDeclaration(
                identifier="xs",
                value=ListExpression(
                    elements=[IntegerLiteral(1), SpreadOperator(Identifier("more"))],
                ),
            ),
            WithDeclaration(
                identifier="mapping",
                value=DictExpression(
                    items=[
                        DictItem(key=Identifier("key"), value=IntegerLiteral(1)),
                        DictItem(
                            key=Identifier("base"),
                            value=SpreadOperator(Identifier("defaults"), is_dict=True),
                        ),
                    ],
                ),
            ),
            WithDeclaration(
                identifier="pair",
                value=TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)]),
            ),
            WithDeclaration(
                identifier="first",
                value=TupleIndexing(
                    tuple_expr=TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)]),
                    index=IntegerLiteral(0),
                ),
            ),
            WithDeclaration(
                identifier="head",
                value=SliceExpression(target=Identifier("xs"), stop=IntegerLiteral(2)),
            ),
            WithDeclaration(
                identifier="predicate",
                value=LambdaExpression(
                    parameters=["x"],
                    body=BinaryExpression(Identifier("x"), ">", IntegerLiteral(0)),
                ),
            ),
            WithDeclaration(
                identifier="positive",
                value=ArrayComprehension(
                    expression=Identifier("x"),
                    variable="x",
                    iterable=Identifier("xs"),
                    condition=BinaryExpression(Identifier("x"), ">", IntegerLiteral(0)),
                ),
            ),
            WithDeclaration(
                identifier="indexed",
                value=DictComprehension(
                    key_expression=Identifier("k"),
                    value_expression=Identifier("v"),
                    key_variable="k",
                    value_variable="v",
                    iterable=Identifier("mapping"),
                ),
            ),
        ],
        body=PatternMatch(
            value=Identifier("first"),
            cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
            default=BooleanLiteral(False),
        ),
    )
    ast = YaraFile(rules=[Rule(name="yarax_pb", condition=condition)])
    serializer = ProtobufSerializer(include_metadata=False)

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.rules[0].condition == condition


@pytest.mark.parametrize("parameters", [cast(Any, "xy"), cast(Any, ["x", 1])])
def test_protobuf_serializer_rejects_invalid_lambda_parameters(parameters: Any) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_lambda",
                condition=LambdaExpression(parameters, BooleanLiteral(True)),
            )
        ],
    )

    with pytest.raises(
        SerializationError,
        match="LambdaExpression parameters must be a list of strings",
    ):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            WithStatement(
                [WithDeclaration(cast(Any, 123), IntegerLiteral(1))],
                BooleanLiteral(True),
            ),
            "WithDeclaration identifier must be a string",
        ),
        (
            ArrayComprehension(variable=cast(Any, 123)),
            "ArrayComprehension variable must be a string",
        ),
        (
            DictComprehension(key_variable=cast(Any, 123)),
            "DictComprehension key_variable must be a string",
        ),
        (
            DictComprehension(key_variable="k", value_variable=cast(Any, 123)),
            "DictComprehension value_variable must be a string",
        ),
        (
            SpreadOperator(Identifier("items"), is_dict=cast(Any, "true")),
            "SpreadOperator is_dict must be a boolean",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_yarax_scalar_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_yarax_scalar", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _invalid_yarax_container_cases() -> list[tuple[Any, str]]:
    with_bad_declarations = WithStatement(
        [WithDeclaration("x", IntegerLiteral(1))],
        BooleanLiteral(True),
    )
    cast(Any, with_bad_declarations).declarations = False

    with_bad_declaration_item = WithStatement(
        [WithDeclaration("x", IntegerLiteral(1))],
        BooleanLiteral(True),
    )
    cast(Any, with_bad_declaration_item).declarations = [object()]

    dict_with_bad_items = DictExpression([DictItem(Identifier("key"), IntegerLiteral(1))])
    cast(Any, dict_with_bad_items).items = False

    dict_with_bad_item = DictExpression([DictItem(Identifier("key"), IntegerLiteral(1))])
    cast(Any, dict_with_bad_item).items = [object()]

    match_with_bad_cases = PatternMatch(
        Identifier("subject"),
        [MatchCase(IntegerLiteral(1), BooleanLiteral(True))],
    )
    cast(Any, match_with_bad_cases).cases = False

    match_with_bad_case = PatternMatch(
        Identifier("subject"),
        [MatchCase(IntegerLiteral(1), BooleanLiteral(True))],
    )
    cast(Any, match_with_bad_case).cases = [object()]

    tuple_with_bad_elements = TupleExpression([IntegerLiteral(1)])
    cast(Any, tuple_with_bad_elements).elements = False

    tuple_with_bad_element = TupleExpression([IntegerLiteral(1)])
    cast(Any, tuple_with_bad_element).elements = [object()]

    list_with_bad_elements = ListExpression([IntegerLiteral(1)])
    cast(Any, list_with_bad_elements).elements = False

    list_with_bad_element = ListExpression([IntegerLiteral(1)])
    cast(Any, list_with_bad_element).elements = [object()]

    return [
        (with_bad_declarations, "WithStatement declarations must be a list"),
        (with_bad_declaration_item, "WithStatement declarations item must be"),
        (dict_with_bad_items, "DictExpression items must be a list"),
        (dict_with_bad_item, "DictExpression items item must be"),
        (match_with_bad_cases, "PatternMatch cases must be a list"),
        (match_with_bad_case, "PatternMatch cases item must be"),
        (tuple_with_bad_elements, "TupleExpression elements must be a list"),
        (tuple_with_bad_element, "TupleExpression elements item must be Expression"),
        (list_with_bad_elements, "ListExpression elements must be a list"),
        (list_with_bad_element, "ListExpression elements item must be Expression"),
    ]


@pytest.mark.parametrize(("condition", "message"), _invalid_yarax_container_cases())
def test_protobuf_serializer_rejects_invalid_yarax_container_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_yarax_container", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            WithStatement([WithDeclaration("", IntegerLiteral(1))], BooleanLiteral(True)),
            "WithDeclaration identifier must not be empty",
        ),
        (
            ArrayComprehension(
                expression=Identifier("x"),
                variable="",
                iterable=Identifier("xs"),
            ),
            "ArrayComprehension variable must not be empty",
        ),
        (
            DictComprehension(
                key_expression=Identifier("k"),
                value_expression=Identifier("v"),
                key_variable="",
                iterable=Identifier("xs"),
            ),
            "DictComprehension key_variable must not be empty",
        ),
        (
            DictComprehension(
                key_expression=Identifier("k"),
                value_expression=Identifier("v"),
                key_variable="k",
                value_variable="",
                iterable=Identifier("xs"),
            ),
            "DictComprehension value_variable must not be empty",
        ),
        (
            LambdaExpression(parameters=[""], body=BooleanLiteral(True)),
            "LambdaExpression parameters item must not be empty",
        ),
    ],
)
def test_protobuf_serializer_rejects_empty_yarax_identifier_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="empty_yarax_identifier", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            ArrayComprehension(
                expression=Identifier("x"),
                variable="1bad",
                iterable=Identifier("xs"),
            ),
            "Invalid local variable identifier: 1bad",
        ),
        (
            DictComprehension(
                key_expression=Identifier("k"),
                value_expression=Identifier("v"),
                key_variable="for",
                iterable=Identifier("xs"),
            ),
            "Invalid local variable identifier: for",
        ),
        (
            DictComprehension(
                key_expression=Identifier("k"),
                value_expression=Identifier("v"),
                key_variable="k",
                value_variable="bad-name",
                iterable=Identifier("xs"),
            ),
            "Invalid local variable identifier: bad-name",
        ),
        (
            LambdaExpression(parameters=["1bad"], body=BooleanLiteral(True)),
            "Invalid local variable identifier: 1bad",
        ),
        (
            WithStatement([WithDeclaration("bad-name", IntegerLiteral(1))], BooleanLiteral(True)),
            "Invalid local variable identifier: bad-name",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_yarax_local_identifier_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_yarax_identifier", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("payload_kind", "message"),
    [
        ("with_declaration", "WithDeclaration identifier must not be empty"),
        ("array_comprehension", "ArrayComprehension variable must not be empty"),
        ("dict_key_variable", "DictComprehension key_variable must not be empty"),
        ("dict_value_variable", "DictComprehension value_variable must not be empty"),
        ("lambda_parameter", "LambdaExpression parameters item must not be empty"),
    ],
)
def test_protobuf_deserializer_rejects_empty_yarax_identifier_fields(
    payload_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_yarax_identifier"
    condition = pb_rule.condition
    if payload_kind == "with_declaration":
        declaration = condition.with_statement.declarations.add()
        declaration.identifier = ""
        declaration.value.integer_literal.value = 1
        condition.with_statement.body.boolean_literal.value = True
    elif payload_kind == "array_comprehension":
        condition.array_comprehension.expression.identifier.name = "x"
        condition.array_comprehension.variable = ""
        condition.array_comprehension.iterable.identifier.name = "xs"
    elif payload_kind == "dict_key_variable":
        condition.dict_comprehension.key_expression.identifier.name = "k"
        condition.dict_comprehension.value_expression.identifier.name = "v"
        condition.dict_comprehension.key_variable = ""
        condition.dict_comprehension.iterable.identifier.name = "xs"
    elif payload_kind == "dict_value_variable":
        condition.dict_comprehension.key_expression.identifier.name = "k"
        condition.dict_comprehension.value_expression.identifier.name = "v"
        condition.dict_comprehension.key_variable = "k"
        condition.dict_comprehension.value_variable = ""
        condition.dict_comprehension.iterable.identifier.name = "xs"
    elif payload_kind == "lambda_parameter":
        condition.lambda_expression.parameters.append("")
        condition.lambda_expression.body.boolean_literal.value = True

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("payload_kind", "message"),
    [
        ("with_declaration", "Invalid local variable identifier: bad-name"),
        ("array_comprehension", "Invalid local variable identifier: 1bad"),
        ("dict_key_variable", "Invalid local variable identifier: for"),
        ("dict_value_variable", "Invalid local variable identifier: bad-name"),
        ("lambda_parameter", "Invalid local variable identifier: 1bad"),
    ],
)
def test_protobuf_deserializer_rejects_invalid_yarax_local_identifier_fields(
    payload_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_yarax_identifier"
    condition = pb_rule.condition
    if payload_kind == "with_declaration":
        declaration = condition.with_statement.declarations.add()
        declaration.identifier = "bad-name"
        declaration.value.integer_literal.value = 1
        condition.with_statement.body.boolean_literal.value = True
    elif payload_kind == "array_comprehension":
        condition.array_comprehension.expression.identifier.name = "x"
        condition.array_comprehension.variable = "1bad"
        condition.array_comprehension.iterable.identifier.name = "xs"
    elif payload_kind == "dict_key_variable":
        condition.dict_comprehension.key_expression.identifier.name = "k"
        condition.dict_comprehension.value_expression.identifier.name = "v"
        condition.dict_comprehension.key_variable = "for"
        condition.dict_comprehension.iterable.identifier.name = "xs"
    elif payload_kind == "dict_value_variable":
        condition.dict_comprehension.key_expression.identifier.name = "k"
        condition.dict_comprehension.value_expression.identifier.name = "v"
        condition.dict_comprehension.key_variable = "k"
        condition.dict_comprehension.value_variable = "bad-name"
        condition.dict_comprehension.iterable.identifier.name = "xs"
    elif payload_kind == "lambda_parameter":
        condition.lambda_expression.parameters.append("1bad")
        condition.lambda_expression.body.boolean_literal.value = True

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())
