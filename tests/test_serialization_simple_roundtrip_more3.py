"""Additional tests for simple roundtrip serializer (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from simple_roundtrip_support import SimpleRoundTrip, SimpleRoundtripSerializer
from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, IntegerLiteral
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import SerializationError
from yaraast.parser import Parser


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


def test_simple_roundtrip_file_io_preserves_plain_string_bytes(tmp_path: Path) -> None:
    serializer = SimpleRoundtripSerializer()
    ast = YaraFile(
        rules=[
            Rule(
                name="bytes_rule",
                strings=[PlainString(identifier="$b", value=b'A"\x00\xff\\\n')],
                condition=BooleanLiteral(value=True),
            )
        ],
    )

    file_path = tmp_path / "ast.json"
    serializer.serialize_to_file(ast, file_path)

    data = json.loads(file_path.read_text(encoding="utf-8"))
    serialized_string = data["rules"][0]["strings"][0]
    assert serialized_string["value_encoding"] == "base64"
    assert isinstance(serialized_string["value"], str)

    restored = serializer.deserialize_from_file(file_path)
    assert isinstance(restored, YaraFile)
    restored_string = restored.rules[0].strings[0]

    assert isinstance(restored_string, PlainString)
    assert restored_string.value == b'A"\x00\xff\\\n'


def test_simple_roundtrip_preserves_anonymous_strings_for_codegen() -> None:
    serializer = SimpleRoundtripSerializer()
    ast = Parser(
        'rule r { strings: $ = "abc" $ = { 41 } $ = /def/ condition: any of them }'
    ).parse()

    restored = serializer.deserialize(serializer.serialize(ast))
    assert isinstance(restored, YaraFile)
    restored_strings = restored.rules[0].strings

    assert [string.is_anonymous for string in restored_strings] == [True, True, True]
    output = CodeGenerator().generate(restored)
    assert '$ = "abc"' in output
    assert "$ = { 41 }" in output
    assert "$ = /def/" in output
    assert "$anon_" not in output


def test_simple_roundtrip_preserves_alias_and_modifiers() -> None:
    serializer = SimpleRoundtripSerializer()
    ast = YaraFile(
        imports=[Import(module="pe", alias="p")],
        rules=[
            Rule(
                name="r1",
                modifiers=["private"],
                strings=[
                    PlainString(
                        identifier="$a",
                        value="x",
                        modifiers=[StringModifier.from_name_value("nocase")],
                    ),
                    HexString(
                        identifier="$h",
                        tokens=[HexByte(value=0x41)],
                        modifiers=[StringModifier.from_name_value("wide")],
                    ),
                    RegexString(
                        identifier="$r",
                        regex="ab",
                        modifiers=[StringModifier.from_name_value("ascii")],
                    ),
                ],
                condition=BooleanLiteral(value=True),
            )
        ],
    )

    restored = serializer.deserialize(serializer.serialize(ast))

    assert isinstance(restored, YaraFile)
    assert restored.imports[0].alias == "p"
    assert str(restored.rules[0].modifiers[0]) == "private"
    assert restored.rules[0].strings[0].modifiers[0].name == "nocase"
    assert restored.rules[0].strings[1].modifiers[0].name == "wide"
    assert restored.rules[0].strings[2].modifiers[0].name == "ascii"


def test_simple_roundtrip_rejects_invalid_xor_modifier_strings() -> None:
    serializer = SimpleRoundtripSerializer()
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("xor", "zz")],
                    )
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    with pytest.raises(SerializationError, match="xor value must be a byte"):
        serializer.serialize(ast)


def test_simple_roundtrip_rejects_utf8_surrogate_modifier_strings() -> None:
    serializer = SimpleRoundtripSerializer()
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("base64", "\ud800")],
                    )
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    with pytest.raises(
        SerializationError,
        match="String modifier value text must be UTF-8 encodable",
    ):
        serializer.serialize(ast)


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
    file_path.write_text(source, encoding="utf-8")
    ok, _, _ = runner.test_file(file_path)
    assert ok is True

    yara_path = tmp_path / "r2.yara"
    yara_path.write_text("rule r2 { condition: true }", encoding="utf-8")
    directory_results = runner.test_directory(tmp_path)

    assert {path.name for path, _, _, _ in directory_results} == {"r1.yar", "r2.yara"}
    assert all(success for _, success, _, _ in directory_results)
