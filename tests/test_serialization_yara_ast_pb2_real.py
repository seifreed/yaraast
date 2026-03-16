"""Real coverage tests for generated protobuf module."""

from __future__ import annotations

import importlib
import os
import sys


def _purge_protobuf_and_serialization_modules() -> None:
    for name in list(sys.modules):
        if name.startswith("google.protobuf"):
            sys.modules.pop(name, None)
        if name.startswith("yaraast.serialization"):
            sys.modules.pop(name, None)


def test_yara_ast_pb2_python_impl_executes_generated_descriptor_block() -> None:
    # Force pure-python protobuf implementation so generated assignment block runs.
    os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    _purge_protobuf_and_serialization_modules()

    pb2 = importlib.import_module("yaraast.serialization.yara_ast_pb2")

    # Validate generated descriptor metadata is populated.
    assert pb2.DESCRIPTOR is not None
    assert pb2._YARAFILE._serialized_start > 0
    assert pb2._RULE._serialized_end > pb2._RULE._serialized_start

    # Exercise a broad set of generated messages/oneofs.
    yf = pb2.YaraFile()
    yf.imports.add(module="pe", alias="p")
    yf.includes.add(path="common.yar")
    rule = yf.rules.add(name="r")
    rule.modifiers.append("private")
    rule.tags.add(name="tag")
    rule.meta["author"].string_value = "me"
    s = rule.strings.add(identifier="$a")
    s.plain.value = "abc"
    s.plain.modifiers.add(name="nocase")
    assert s.WhichOneof("string_type") == "plain"

    hx = rule.strings.add(identifier="$h")
    t1 = hx.hex.tokens.add()
    t1.byte.value = "90"
    t2 = hx.hex.tokens.add()
    t2.wildcard.SetInParent()
    t3 = hx.hex.tokens.add()
    t3.jump.min_jump = 1
    t3.jump.max_jump = 2
    t4 = hx.hex.tokens.add()
    t4.nibble.high = True
    t4.nibble.value = 10
    assert t4.WhichOneof("token_type") == "nibble"

    rx = rule.strings.add(identifier="$r")
    rx.regex.regex = "ab+"
    rx.regex.modifiers.add(name="wide")
    assert rx.WhichOneof("string_type") == "regex"

    expr = pb2.Expression()
    expr.binary_expression.left.boolean_literal.value = True
    expr.binary_expression.operator = "and"
    expr.binary_expression.right.defined_expression.expression.identifier.name = "x"
    rule.condition.CopyFrom(expr)
    assert rule.condition.WhichOneof("expression_type") == "binary_expression"

    # Ensure serialization round-trip works for full message.
    data = yf.SerializeToString()
    parsed = pb2.YaraFile()
    parsed.ParseFromString(data)
    assert parsed.rules[0].name == "r"

    # Keep current protobuf module state for this process; re-switching implementation
    # in-process is unsupported by protobuf runtime internals.
    os.environ.pop("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", None)
