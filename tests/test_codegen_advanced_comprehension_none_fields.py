"""Regression tests for AdvancedCodeGenerator on comprehension nodes with None fields.

A YARA-X array/dict comprehension declares ``expression``, ``iterable``, and the
dict key/value expressions as optional (``Expression | None``). When such a node
is constructed programmatically with those fields left at their ``None`` default,
the AdvancedCodeGenerator previously called ``self.visit(None)`` and crashed with
a non-clean ``TypeError: Visitor node must be an ASTNode``. It must instead raise
a clean ``ValueError`` describing the missing required field.
"""

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    Expression,
    Identifier,
    IntegerLiteral,
)
from yaraast.ast.rules import Rule
from yaraast.codegen.formatting import FormattingConfig
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.yarax.ast_nodes import ArrayComprehension, DictComprehension


def _wrap(condition: Expression) -> YaraFile:
    return YaraFile(rules=[Rule(name="r", condition=condition)])


@pytest.mark.parametrize(
    "node",
    [
        ArrayComprehension(expression=None, variable="x", iterable=Identifier("a")),
        ArrayComprehension(expression=Identifier("a"), variable="x", iterable=None),
    ],
)
def test_array_comprehension_missing_field_raises_value_error(node: ArrayComprehension) -> None:
    with pytest.raises(ValueError, match="ArrayComprehension"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(_wrap(node))


@pytest.mark.parametrize(
    "node",
    [
        DictComprehension(
            key_expression=None,
            value_expression=Identifier("a"),
            key_variable="k",
            iterable=Identifier("it"),
        ),
        DictComprehension(
            key_expression=Identifier("a"),
            value_expression=None,
            key_variable="k",
            iterable=Identifier("it"),
        ),
        DictComprehension(
            key_expression=Identifier("a"),
            value_expression=Identifier("b"),
            key_variable="k",
            iterable=None,
        ),
    ],
)
def test_dict_comprehension_missing_field_raises_value_error(node: DictComprehension) -> None:
    with pytest.raises(ValueError, match="DictComprehension"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(_wrap(node))


def test_fully_specified_comprehension_still_generates() -> None:
    node = ArrayComprehension(
        expression=BinaryExpression(Identifier("x"), "*", IntegerLiteral(2)),
        variable="x",
        iterable=Identifier("items"),
    )
    output = CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(
        _wrap(node)
    )
    assert "for x in" in output
