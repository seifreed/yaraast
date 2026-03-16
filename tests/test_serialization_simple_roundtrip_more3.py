"""Additional tests for simple roundtrip serializer (no mocks)."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, IntegerLiteral
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString, RegexString
from yaraast.serialization.simple_roundtrip import SimpleRoundTrip, SimpleRoundtripSerializer


def _sample_ast() -> YaraFile:
    rule = Rule(
        name="r1",
        tags=[Tag(name="t1")],
        meta={"author": "me"},
        strings=[PlainString(identifier="$a", value="x"), RegexString(identifier="$b", regex="ab")],
        condition=BooleanLiteral(value=True),
    )
    return YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[rule],
    )


def test_simple_roundtrip_serialize_deserialize() -> None:
    serializer = SimpleRoundtripSerializer()
    ast = _sample_ast()

    data = serializer.serialize(ast)
    restored = serializer.deserialize(data)

    assert isinstance(restored, YaraFile)
    assert restored.rules[0].name == "r1"


def test_simple_roundtrip_file_io(tmp_path: Path) -> None:
    serializer = SimpleRoundtripSerializer()
    ast = _sample_ast()

    file_path = tmp_path / "ast.json"
    serializer.serialize_to_file(ast, file_path)
    restored = serializer.deserialize_from_file(file_path)

    assert isinstance(restored, YaraFile)
    assert restored.rules[0].strings


def test_simple_roundtrip_validator() -> None:
    serializer = SimpleRoundtripSerializer()
    rule = Rule(name="r1", condition=IntegerLiteral(value=1))

    valid, diff = serializer.validate_roundtrip(rule)
    assert "original_code" in diff
    assert isinstance(valid, bool)


def test_simple_roundtrip_runner_stats(tmp_path: Path) -> None:
    runner = SimpleRoundTrip()
    source = "rule r1 { condition: true }"
    runner.test(source)

    stats = runner.get_statistics()
    assert stats["total_tests"] == 1
    assert stats["successful_tests"] == 1

    file_path = tmp_path / "r1.yar"
    file_path.write_text(source)
    ok, _, _ = runner.test_file(file_path)
    assert ok is True
