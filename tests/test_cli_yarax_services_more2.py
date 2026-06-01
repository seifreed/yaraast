"""More tests for YARA-X service helpers (no mocks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.cli import yarax_services as ys


def test_yarax_services_detection_helpers() -> None:
    content = (
        "with x = 1: [i for i in (1,2)] {k:v for k,v in d} "
        "lambda x: x match y { _ => true } ... **"
    )
    feats = ys.detect_yarax_features(content)
    assert "with statements" in feats
    assert "array comprehensions" in feats
    assert "dict comprehensions" in feats
    assert "lambda expressions" in feats
    assert "pattern matching" in feats
    assert "spread operators" in feats

    pfeats = ys.detect_playground_features("with x=1: [i for i in a] lambda x: x")
    assert "with statements" in pfeats
    assert "comprehensions" in pfeats
    assert "lambda expressions" in pfeats

    default_code = ys.get_default_playground_code()
    assert "rule yarax_demo" in default_code
    assert "with count" in default_code
    _default_ast, default_generated = ys.parse_yarax_content(default_code)
    assert "rule yarax_demo" in default_generated
    assert "match count" in default_generated
    assert "array comprehensions" in ys.detect_playground_features(default_code)


def test_yarax_services_detect_collection_only_features() -> None:
    content = """
rule collection_features {
    condition:
        [true][0] and {"a": true}["a"] and "abc"[0:1] == "a" and (1, 2)[0] == 1
}
"""

    feats = set(ys.detect_yarax_features(content))

    assert "dict expressions" in feats
    assert "list expressions" in feats
    assert "slice expressions" in feats
    assert "tuple expressions" in feats
    assert "tuple indexing" in feats

    snippet_feats = ys.detect_playground_features('[true][0] and "abc"[0:1] == "a"')
    assert "list expressions" in snippet_feats
    assert "slice expressions" in snippet_feats


def test_yarax_services_detection_helpers_ignore_literals_comments_and_regexes() -> None:
    content = r"""
rule classic {
    meta:
        description = "with xs = [1]: match xs { _ => true } lambda x: x ... **"
    strings:
        $a = /with xs = [1]: match xs { _ => true } lambda x: x ... \*\*/
    condition:
        $a // with xs = [1]: match xs { _ => true } lambda x: x ... **
}
"""

    assert ys.detect_yarax_features(content) == []
    assert ys.detect_playground_features(content) == []


def test_yarax_services_parse_and_convert_roundtrip(tmp_path: Path) -> None:
    yara_code = "rule a { condition: true }"
    yarax_code = "rule b { condition: true }"

    ast, generated = ys.parse_yarax_content(yarax_code)
    assert ast is not None
    assert "rule b" in generated

    converted_to_yarax = ys.convert_yara_to_yarax(yara_code)
    assert "rule a" in converted_to_yarax
    native_yarax = ys.convert_yara_to_yarax(
        "rule x { condition: with xs = [1]: match xs { _ => true } }"
    )
    assert "with xs = [1]" in native_yarax
    assert "match xs" in native_yarax

    converted_to_yara = ys.convert_yarax_to_yara(yarax_code)
    assert "rule b" in converted_to_yara

    file_path = tmp_path / "sample.yar"
    file_path.write_text(yara_code, encoding="utf-8")
    ast_file = ys.parse_yara_file_ast(str(file_path))
    assert len(ast_file.rules) == 1


@pytest.mark.parametrize("content", [None, 123, object()])
def test_yarax_services_parse_rejects_invalid_content_types(content: Any) -> None:
    with pytest.raises(TypeError, match="content must be a string"):
        ys.parse_yarax_content(cast(str, content))


def test_yarax_to_yara_conversion_rejects_yarax_only_syntax() -> None:
    yarax_code = """
rule native_yarax {
    condition:
        with xs = [1]: match xs { 1 => true, _ => false }
}
"""

    with pytest.raises(ValueError) as exc_info:
        ys.convert_yarax_to_yara(yarax_code)
    message = str(exc_info.value)
    assert "Cannot convert YARA-X-only syntax to standard YARA" in message
    assert "pattern matching" in message
    assert "with statements" in message


@pytest.mark.parametrize("content", [None, 123, object()])
def test_yarax_to_yara_conversion_rejects_invalid_content_types(content: Any) -> None:
    with pytest.raises(TypeError, match="content must be a string"):
        ys.convert_yarax_to_yara(cast(str, content))


def test_yarax_services_compatibility_check() -> None:
    ast, _generated = ys.parse_yarax_content("rule c { condition: true }")
    result_non_strict = ys.check_yarax_compatibility(ast, strict=False)
    result_strict = ys.check_yarax_compatibility(ast, strict=True)
    assert result_non_strict is not None
    assert result_strict is not None
    assert ast is not None


@pytest.mark.parametrize("strict", [None, 1, "yes", object()])
def test_yarax_services_compatibility_check_rejects_invalid_strict_types(
    strict: Any,
) -> None:
    ast, _generated = ys.parse_yarax_content("rule c { condition: true }")

    with pytest.raises(TypeError, match="strict must be a boolean"):
        ys.check_yarax_compatibility(ast, strict=cast(bool, strict))
