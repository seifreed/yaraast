from __future__ import annotations

import json

from yaraast.ast.base import YaraFile
from yaraast.cli.visitors import ASTDumper
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.visitor.transformer_impl import ASTTransformer
from yaraast.yarax.ast_nodes import (
    DictComprehension,
    DictExpression,
    LambdaExpression,
    ListExpression,
    PatternMatch,
    SliceExpression,
    TupleExpression,
    WithStatement,
)
from yaraast.yarax.parser import YaraXParser


def test_yarax_nodes_are_supported_by_serializers_and_generic_visitors() -> None:
    ast = YaraXParser(
        """
rule yarax_serialized {
    condition:
        with xs = [1, ...arr],
             d = {**base, "a": 1},
             t = (1, 2),
             s = arr[1:4:2],
             f = lambda x: foo()[0],
             ac = [x for x in [1, 2] if x],
             dc = {k: v for k, v in data if v}:
            match t { 1 => d, _ => xs }
}
""",
    ).parse()

    condition = ast.rules[0].condition
    assert isinstance(condition, WithStatement)

    values = [declaration.value for declaration in condition.declarations]
    assert isinstance(values[0], ListExpression)
    assert isinstance(values[1], DictExpression)
    assert isinstance(values[2], TupleExpression)
    assert isinstance(values[3], SliceExpression)
    assert isinstance(values[4], LambdaExpression)
    assert isinstance(values[6], DictComprehension)

    serializer = JsonSerializer(include_metadata=False)
    serialized = json.loads(serializer.serialize(ast))
    serialized_condition = serialized["ast"]["rules"][0]["condition"]
    assert serialized_condition["type"] == "WithStatement"
    assert serialized_condition["declarations"][0]["value"]["type"] == "ListExpression"
    assert serialized_condition["declarations"][6]["value"]["type"] == "DictComprehension"
    assert serialized_condition["body"]["type"] == "PatternMatch"

    restored = serializer.deserialize(json.dumps(serialized))
    restored_condition = restored.rules[0].condition
    assert isinstance(restored_condition, WithStatement)
    assert isinstance(restored_condition.declarations[6].value, DictComprehension)
    assert isinstance(restored_condition.body, PatternMatch)

    dumped = ASTDumper().visit(ast)
    dumped_condition = dumped["rules"][0]["condition"]
    assert dumped_condition["type"] == "WithStatement"
    assert dumped_condition["body"]["type"] == "PatternMatch"

    transformed = ASTTransformer().visit(ast)
    assert isinstance(transformed, YaraFile)
    assert isinstance(transformed.rules[0].condition, WithStatement)
