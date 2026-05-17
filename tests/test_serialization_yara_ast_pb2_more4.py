"""More tests for protobuf schema message shapes (no mocks)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_hex_token_alternatives_and_nibble() -> None:
    pb2 = pytest.importorskip("yaraast.serialization.yara_ast_pb2")

    token = pb2.HexToken()
    token.nibble.high = True
    token.nibble.value = 10
    assert token.WhichOneof("token_type") == "nibble"

    alt = pb2.HexAlternative()
    seq = alt.alternatives.add()
    seq.tokens.add().byte.value = "90"
    seq.tokens.add().wildcard.SetInParent()
    assert alt.alternatives[0].tokens[0].WhichOneof("token_type") == "byte"


def test_meta_value_oneof_switch() -> None:
    pb2 = pytest.importorskip("yaraast.serialization.yara_ast_pb2")

    meta = pb2.MetaValue()
    meta.string_value = "x"
    assert meta.WhichOneof("value") == "string_value"

    meta.int_value = 5
    assert meta.WhichOneof("value") == "int_value"


def test_string_definition_oneof() -> None:
    pb2 = pytest.importorskip("yaraast.serialization.yara_ast_pb2")

    string_def = pb2.StringDefinition()
    string_def.identifier = "$a"
    string_def.regex.regex = "ab.*"
    assert string_def.WhichOneof("string_type") == "regex"


def test_string_definition_anonymous_field_is_in_runtime_and_stub() -> None:
    pb2 = pytest.importorskip("yaraast.serialization.yara_ast_pb2")

    string_def = pb2.StringDefinition(identifier="$anon_1", is_anonymous=True)

    assert string_def.is_anonymous is True
    assert string_def.DESCRIPTOR.fields_by_name["is_anonymous"].number == 6

    stub_text = Path(pb2.__file__).with_suffix(".pyi").read_text(encoding="utf-8")
    assert "IS_ANONYMOUS_FIELD_NUMBER" in stub_text
    assert "is_anonymous: bool" in stub_text
    assert "is_anonymous: bool | None = ..." in stub_text
