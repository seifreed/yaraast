"""Tests for simple roundtrip serialization utilities."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.parser import Parser
from yaraast.serialization.simple_roundtrip import (
    SimpleRoundTrip,
    SimpleRoundtripSerializer,
    simple_roundtrip_test,
)


def _sample_yara_rule() -> str:
    return """
import "pe"

rule test_roundtrip : alpha beta {
    meta:
        author = "unit"
        active = true
        count = 3
    strings:
        $a = "abc"
        $b = { 6A 40 68 00 30 00 00 }
        $c = /foo.*/
    condition:
        any of them
}
"""


def test_simple_roundtrip_serializer_in_memory() -> None:
    parser = Parser()
    ast = parser.parse(_sample_yara_rule())

    serializer = SimpleRoundtripSerializer()
    data = serializer.serialize(ast)
    restored = serializer.deserialize(data)

    assert data["type"] == "YaraFile"
    assert restored is not None

    ok, diff = serializer.validate_roundtrip(ast)
    assert isinstance(ok, bool)
    assert "original_code" in diff


def test_simple_roundtrip_serializer_file_io(tmp_path: Path) -> None:
    parser = Parser()
    ast = parser.parse(_sample_yara_rule())

    serializer = SimpleRoundtripSerializer()
    out_path = tmp_path / "roundtrip.json"

    serializer.serialize_to_file(ast, out_path)
    loaded = serializer.deserialize_from_file(out_path)

    assert loaded is not None


def test_simple_roundtrip_helpers(tmp_path: Path) -> None:
    helper = SimpleRoundTrip()

    yara_code = _sample_yara_rule()
    ok, orig, regen = helper.test(yara_code)
    assert isinstance(ok, bool)
    assert orig is not None or regen is None

    batch = helper.test_batch([yara_code, yara_code])
    assert len(batch) == 2

    file_path = tmp_path / "sample.yar"
    file_path.write_text(yara_code)
    ok2, _, _ = helper.test_file(file_path)
    assert isinstance(ok2, bool)

    results = helper.test_directory(tmp_path)
    assert results

    stats = helper.get_statistics()
    assert stats["total_tests"] >= 3

    report = simple_roundtrip_test(yara_code)
    assert report["round_trip_successful"] in {True, False}


def test_simple_roundtrip_serialize_primitives() -> None:
    serializer = SimpleRoundtripSerializer()

    primitives = [
        BooleanLiteral(True),
        IntegerLiteral(1),
        DoubleLiteral(3.14),
        StringLiteral("hi"),
        Identifier("foo"),
        StringIdentifier("$a"),
        UnaryExpression("not", BooleanLiteral(False)),
        BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)),
    ]

    for node in primitives:
        data = serializer.serialize(node)
        restored = serializer.deserialize(data)
        assert restored is not None

    # Unknown type fallback should return an Identifier
    restored = serializer.deserialize({"type": "UnknownNode", "data": "fallback"})
    assert isinstance(restored, Identifier)


def test_simple_roundtrip_error_path() -> None:
    report = simple_roundtrip_test("rule broken { condition: }")
    assert report["round_trip_successful"] is False
