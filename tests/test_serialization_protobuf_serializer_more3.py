"""More tests for Protobuf serializer (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import StringIdentifier
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexNibble, HexString, PlainString
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def test_protobuf_serializer_stats_and_modifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=True)
    rule = Rule(
        name="r1",
        strings=[
            PlainString(
                identifier="$a",
                value="x",
                modifiers=[StringModifier.from_name_value("xor", "10")],
            ),
            HexString(
                identifier="$b", tokens=[HexByte(value=0x90), HexNibble(high=False, value=0xA)]
            ),
        ],
        condition=StringIdentifier(name="$a"),
    )
    ast = YaraFile(rules=[rule])

    stats = serializer.get_serialization_stats(ast)
    assert stats["rules_count"] == 1
    assert stats["binary_size_bytes"] > 0

    text = serializer.serialize_text(ast)
    assert "metadata" in text


def test_protobuf_serializer_empty_data_error() -> None:
    serializer = ProtobufSerializer()
    with pytest.raises(ValueError):
        serializer.deserialize(binary_data=b"")
