"""More tests for YARA-X service helpers (no mocks)."""

from __future__ import annotations

from pathlib import Path

from yaraast.cli import yarax_services as ys


def test_yarax_services_detection_helpers() -> None:
    content = "with x = 1: [i for i in (1,2)] {k:v for k,v in d} lambda x: x match y ... **"
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
    assert "with $count" in default_code


def test_yarax_services_parse_and_convert_roundtrip(tmp_path: Path) -> None:
    yara_code = "rule a { condition: true }"
    yarax_code = "rule b { condition: true }"

    ast, generated = ys.parse_yarax_content(yarax_code)
    assert ast is not None
    assert "rule b" in generated

    converted_to_yarax = ys.convert_yara_to_yarax(yara_code)
    assert "rule a" in converted_to_yarax

    converted_to_yara = ys.convert_yarax_to_yara(yarax_code)
    assert "rule b" in converted_to_yara

    file_path = tmp_path / "sample.yar"
    file_path.write_text(yara_code, encoding="utf-8")
    ast_file = ys.parse_yara_file_ast(str(file_path))
    assert len(ast_file.rules) == 1


def test_yarax_services_compatibility_check() -> None:
    ast, _generated = ys.parse_yarax_content("rule c { condition: true }")
    result_non_strict = ys.check_yarax_compatibility(ast, strict=False)
    result_strict = ys.check_yarax_compatibility(ast, strict=True)
    assert result_non_strict is not None
    assert result_strict is not None
    assert ast is not None
