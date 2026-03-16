"""Additional real coverage for simple_roundtrip_helpers."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString, StringDefinition
from yaraast.serialization.simple_roundtrip_helpers import (
    _compare_normalized,
    deserialize_from_file,
    deserialize_meta,
    deserialize_rule,
    deserialize_string,
    serialize_meta,
    serialize_rule,
    serialize_string,
    serialize_to_file,
    validate_roundtrip,
)


def test_simple_roundtrip_helpers_serialize_meta_and_string_fallbacks(tmp_path: Path) -> None:
    rule = Rule(
        name="helper_rule",
        condition=BooleanLiteral(value=True),
        tags=[Tag(name="one"), "two"],
        meta=[Meta(key="author", value="me"), Meta(key="enabled", value=True)],
        strings=[
            PlainString(identifier="$a", value="x"),
            HexString(identifier="$b", tokens=[HexByte(value=0x41)]),
            RegexString(identifier="$c", regex="ab.*"),
        ],
    )

    serialized_rule = serialize_rule(rule)
    assert serialized_rule["meta"][0] == {"type": "Meta", "key": "author", "value": "me"}
    assert serialize_meta(Meta(key="score", value=7)) == {
        "type": "Meta",
        "key": "score",
        "value": 7,
    }
    assert serialize_string(StringDefinition(identifier="$z"))["type"] == "StringDefinition"

    restored_rule = deserialize_rule(serialized_rule)
    assert restored_rule.tags == ["one", "two"]
    assert deserialize_meta({"key": "author", "value": "me"}).key == "author"
    assert deserialize_string({"type": "Unknown", "identifier": "$x", "data": "raw"}).value == "raw"

    path = tmp_path / "helper.json"
    serialize_to_file(
        YaraFile(imports=[Import(module="pe")], includes=[Include(path="inc.yar")], rules=[rule]),
        path,
    )
    restored_file = deserialize_from_file(path)
    assert isinstance(restored_file, YaraFile)
    assert restored_file.rules[0].name == "helper_rule"


def test_simple_roundtrip_helpers_compare_and_error_paths(tmp_path: Path) -> None:
    ok, differences = _compare_normalized("a\nb\nc", "a\nb\nc")
    assert ok is True
    assert differences == []

    ok_equal_len, differences_equal_len = _compare_normalized("a\nb\nc", "a\nx\nc")
    assert ok_equal_len is False
    assert differences_equal_len == ["Line 2 differs: 'b' vs 'x'"]

    ok2, differences2 = _compare_normalized(
        "1\n2\n3\n4\n5\n6\n7\n8",
        "x\ny\nz\nu\nv\nw",
    )
    assert ok2 is False
    assert differences2[0].startswith("Line count differs:")
    assert differences2[-1] == "... more differences"

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not-json")
    try:
        deserialize_from_file(bad_json)
    except Exception:
        pass
    else:
        raise AssertionError("deserialize_from_file should fail on invalid JSON")

    valid, diff = validate_roundtrip(None)  # type: ignore[arg-type]
    assert valid is False
    assert "error" in diff

    fallback = deserialize_string({"type": "HexString", "identifier": "$h", "tokens": "{ 41 }"})
    assert isinstance(fallback, PlainString)
    assert fallback.value == "{ 41 }"

    default_condition_rule = deserialize_rule({"name": "fallback", "condition": None})
    assert isinstance(default_condition_rule.condition, BooleanLiteral)
