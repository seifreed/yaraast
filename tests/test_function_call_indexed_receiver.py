"""Function calls whose receiver indexes into an array or dictionary.

``pe.signatures[i].valid_on(t)`` is the only libyara function declared inside a
struct array. Its receiver (``pe.signatures[i]``) cannot be flattened to a
dotted name without losing the index, so ``FunctionCall`` carries it as a
``receiver`` expression. Before this support the parser collapsed the callee to
``unknown.valid_on`` and the validator emitted a false positive on a rule
libyara accepts. These tests pin the parser representation, validation,
code-generation round trip, and both serialization paths.
"""

from __future__ import annotations

from typing import cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import ArrayAccess, BinaryExpression, Expression, FunctionCall
from yaraast.codegen import CodeGenerator
from yaraast.parser.parser import Parser
from yaraast.parser.source import parse_source
from yaraast.serialization import JsonSerializer, ProtobufSerializer, YamlSerializer
from yaraast.serialization.ast_diff_hasher import AstHasher
from yaraast.types.semantic_validator import SemanticValidator
from yaraast.yarax.ast_nodes import ListExpression, TupleIndexing

yara = pytest.importorskip("yara")

_VALID_ON = 'import "pe"\nrule r { condition: pe.signatures[0].valid_on(pe.timestamp) }'


def _condition(source: str) -> Expression:
    condition = Parser(source).parse().rules[0].condition
    assert isinstance(condition, Expression)
    return condition


def test_parser_keeps_indexed_receiver_as_expression() -> None:
    call = _condition(_VALID_ON)
    assert isinstance(call, FunctionCall)
    assert call.function == "valid_on"
    assert isinstance(call.receiver, ArrayAccess)
    assert call.module_and_function() == ("pe", "signatures.valid_on")
    assert call.qualified_name() == "pe.signatures.valid_on"


def test_plain_and_struct_calls_have_no_receiver() -> None:
    for source in (
        'import "pe"\nrule r { condition: pe.imphash() }',
        'import "pe"\nrule r { condition: pe.rich_signature.version(1) }',
        "rule r { condition: uint16(0) }",
    ):
        call = _condition(source)
        assert isinstance(call, FunctionCall)
        assert call.receiver is None


def test_indexed_receiver_call_validates_like_libyara() -> None:
    ast = Parser(_VALID_ON).parse()
    result = SemanticValidator().validate(ast)
    assert result.errors == []
    yara.compile(source=_VALID_ON)  # libyara accepts it too


def test_indexed_receiver_call_round_trips_through_codegen() -> None:
    ast = Parser(_VALID_ON).parse()
    generated = CodeGenerator().generate(ast)
    assert "pe.signatures[0].valid_on(pe.timestamp)" in generated
    yara.compile(source=generated)
    regenerated = CodeGenerator().generate(Parser(generated).parse())
    assert regenerated == generated


def test_indexed_receiver_call_round_trips_through_json() -> None:
    ast = Parser(_VALID_ON).parse()
    serializer = JsonSerializer()
    restored = serializer.deserialize(serializer.serialize(ast))
    assert CodeGenerator().generate(restored) == CodeGenerator().generate(ast)


def test_indexed_receiver_call_round_trips_through_protobuf() -> None:
    ast = Parser(_VALID_ON).parse()
    serializer = ProtobufSerializer()
    restored = serializer.deserialize(serializer.serialize(ast))
    assert CodeGenerator().generate(restored) == CodeGenerator().generate(ast)


def test_diff_hash_distinguishes_receiver_index() -> None:
    first = AstHasher().visit(
        _condition('import "pe"\nrule r { condition: pe.signatures[0].valid_on(0) }')
    )
    second = AstHasher().visit(
        _condition('import "pe"\nrule r { condition: pe.signatures[1].valid_on(0) }')
    )
    assert first != second


def test_unknown_method_on_indexed_receiver_is_reported() -> None:
    ast = Parser('import "pe"\nrule r { condition: pe.signatures[0].nope(0) }').parse()
    result = SemanticValidator().validate(ast)
    assert any("nope" in error.message for error in result.errors)


def test_yarax_literal_receiver_method_call_round_trips() -> None:
    source = "rule r { condition: [1].map(lambda x: x + 1)[0] == 2 }"
    ast = cast(YaraFile, parse_source(source))
    condition = ast.rules[0].condition
    assert isinstance(condition, BinaryExpression)
    access = condition.left
    assert isinstance(access, TupleIndexing)
    call = access.tuple_expr
    assert isinstance(call, FunctionCall)
    assert call.function == "map"
    assert isinstance(call.receiver, ListExpression)

    generated = CodeGenerator().generate(ast)
    assert "unknown.map" not in generated
    assert "[1].map(lambda x: x + 1)[0] == 2" in generated
    assert CodeGenerator().generate(cast(YaraFile, parse_source(generated))) == generated

    for serializer in (JsonSerializer(), YamlSerializer(), ProtobufSerializer()):
        restored = serializer.deserialize(serializer.serialize(ast))
        assert CodeGenerator().generate(restored) == generated
