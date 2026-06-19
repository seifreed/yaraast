"""Tests for simple roundtrip serialization utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from simple_roundtrip_support import (
    SimpleRoundTrip,
    SimpleRoundtripSerializer,
    simple_roundtrip_test,
)
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
from yaraast.errors import SerializationError
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


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


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


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


def test_simple_roundtrip_serializer_validates_yarax_ast() -> None:
    serializer = SimpleRoundtripSerializer()
    ast = parse_yara_source(_yarax_rule())

    ok, diff = serializer.validate_roundtrip(ast)

    assert ok is True
    assert "match xs" in diff["original_code"]


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
    file_path.write_text(yara_code, encoding="utf-8")
    ok2, _, _ = helper.test_file(file_path)
    assert isinstance(ok2, bool)

    results = helper.test_directory(tmp_path)
    assert results

    stats = helper.get_statistics()
    assert stats["total_tests"] >= 3

    report = simple_roundtrip_test(yara_code)
    assert report["round_trip_successful"] in {True, False}


def test_simple_roundtrip_helpers_accept_string_paths(tmp_path: Path) -> None:
    helper = SimpleRoundTrip()
    file_path = tmp_path / "sample.yar"
    file_path.write_text(_sample_yara_rule(), encoding="utf-8")

    file_ok, _, _ = helper.test_file(str(file_path))
    directory_results = helper.test_directory(str(tmp_path))

    assert isinstance(file_ok, bool)
    assert directory_results


@pytest.mark.parametrize("yara_codes", [None, 123, "rule a { condition: true }", object()])
def test_simple_roundtrip_batch_rejects_invalid_batch_types(yara_codes: Any) -> None:
    with pytest.raises(TypeError, match="yara_codes must be a sequence of strings"):
        SimpleRoundTrip().test_batch(cast(list[str], yara_codes))


@pytest.mark.parametrize("yara_codes", [[123], [object()]])
def test_simple_roundtrip_batch_rejects_invalid_batch_items(yara_codes: Any) -> None:
    with pytest.raises(TypeError, match="yara_codes must contain only strings"):
        SimpleRoundTrip().test_batch(cast(list[str], yara_codes))


@pytest.mark.parametrize("file_path", [None, 123, object()])
def test_simple_roundtrip_file_rejects_invalid_path_types(file_path: Any) -> None:
    with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
        SimpleRoundTrip().test_file(cast(Any, file_path))


@pytest.mark.parametrize("file_path", ["", "   ", "\t"])
def test_simple_roundtrip_file_rejects_empty_path(file_path: str) -> None:
    with pytest.raises(ValueError, match="file_path must not be empty"):
        SimpleRoundTrip().test_file(file_path)


def test_simple_roundtrip_file_rejects_invalid_utf8(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yar"
    bad.write_bytes(b"\xff")

    with pytest.raises(ValueError, match="YARA file must contain valid UTF-8 text"):
        SimpleRoundTrip().test_file(bad)


@pytest.mark.parametrize("dir_path", [None, 123, object()])
def test_simple_roundtrip_directory_rejects_invalid_path_types(dir_path: Any) -> None:
    with pytest.raises(TypeError, match="dir_path must be a string or path-like object"):
        SimpleRoundTrip().test_directory(cast(Any, dir_path))


@pytest.mark.parametrize("dir_path", ["", "   ", "\t"])
def test_simple_roundtrip_directory_rejects_empty_path(dir_path: str) -> None:
    with pytest.raises(ValueError, match="dir_path must not be empty"):
        SimpleRoundTrip().test_directory(dir_path)


def test_simple_roundtrip_helpers_accept_yarax() -> None:
    helper = SimpleRoundTrip()

    ok, original_ast, regenerated_ast = helper.test(_yarax_rule())
    report = simple_roundtrip_test(_yarax_rule())

    assert ok is True
    assert original_ast.rules[0].name == "x"
    assert regenerated_ast.rules[0].name == "x"
    assert report["metadata"]["original_rule_count"] == 1
    assert report["metadata"]["reconstructed_rule_count"] == 1
    assert "Error during roundtrip" not in " ".join(report["differences"])


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

    with pytest.raises(SerializationError, match="Unsupported simple AST node type: UnknownNode"):
        serializer.deserialize({"type": "UnknownNode", "data": "fallback"})


def test_simple_roundtrip_error_path() -> None:
    report = simple_roundtrip_test("rule broken { condition: }")
    assert report["round_trip_successful"] is False
