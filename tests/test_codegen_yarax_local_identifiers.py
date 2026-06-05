"""Regression coverage for YARA-X local identifier code generation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.ast.base import ASTNode
from yaraast.ast.expressions import BooleanLiteral, Identifier, IntegerLiteral
from yaraast.codegen import CodeGenerator
from yaraast.codegen.formatting import FormattingConfig
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import PrettyPrintOptions
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    WithDeclaration,
)
from yaraast.yarax.generator import YaraXGenerator


def _plain_generator() -> CodeGenerator:
    return CodeGenerator()


def _pretty_generator() -> CodeGenerator:
    return CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions()))


def _advanced_generator() -> CodeGenerator:
    return CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig()))


def _yarax_generator() -> CodeGenerator:
    return YaraXGenerator()


@pytest.mark.parametrize(
    "generator_factory",
    [_plain_generator, _pretty_generator, _advanced_generator, _yarax_generator],
)
@pytest.mark.parametrize(
    "node",
    [
        WithDeclaration("bad-name", IntegerLiteral(1)),
        WithDeclaration("$bad-name", IntegerLiteral(1)),
        ArrayComprehension(Identifier("x"), "bad-name", Identifier("items")),
        DictComprehension(Identifier("k"), Identifier("v"), "bad-name", None, Identifier("items")),
        DictComprehension(Identifier("k"), Identifier("v"), "k", "bad-name", Identifier("items")),
        LambdaExpression(["bad-name"], BooleanLiteral(True)),
    ],
)
def test_codegen_rejects_invalid_yarax_local_identifiers(
    generator_factory: Callable[[], CodeGenerator],
    node: ASTNode,
) -> None:
    with pytest.raises(ValueError, match=r"Invalid .* identifier"):
        generator_factory().visit(node)


@pytest.mark.parametrize(
    "generator_factory",
    [_plain_generator, _pretty_generator, _advanced_generator, _yarax_generator],
)
def test_codegen_rejects_non_string_yarax_with_local_identifier(
    generator_factory: Callable[[], CodeGenerator],
) -> None:
    node = WithDeclaration(cast(Any, False), IntegerLiteral(1))

    with pytest.raises(TypeError, match="Local variable identifier must be a string"):
        generator_factory().visit(node)


@pytest.mark.parametrize(
    "generator_factory",
    [_plain_generator, _pretty_generator, _advanced_generator, _yarax_generator],
)
def test_codegen_preserves_yarax_with_string_reference_local_identifier(
    generator_factory: Callable[[], CodeGenerator],
) -> None:
    assert generator_factory().visit(WithDeclaration("$x", IntegerLiteral(1))) == "$x = 1"
