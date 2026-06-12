from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE, LibyaraCompiler


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_handles_read_and_save_failures(tmp_path: Path) -> None:
    compiler = LibyaraCompiler()

    directory = tmp_path / "adir"
    directory.mkdir()
    read_result = compiler.compile_file(directory)
    assert read_result.success is False
    assert read_result.errors
    assert "Error reading file" in read_result.errors[0]

    assert compiler.save_compiled_rules(object(), tmp_path / "rules.bin") is False


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_handles_type_error_and_null_byte_source_paths() -> None:
    compiler = LibyaraCompiler()

    type_error_result = compiler.compile_source(cast(Any, None))
    assert type_error_result.success is False
    assert type_error_result.errors
    assert "Unexpected error" in type_error_result.errors[0]

    null_byte_result = compiler.compile_source(
        'rule bad {\nstrings:\n$a = "a\x00b"\ncondition:\n$a\n}\n'
    )
    assert null_byte_result.source_code is not None


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
@pytest.mark.parametrize("filepath", ["", "   ", "\t"])
def test_libyara_compiler_compile_file_rejects_empty_filepath(filepath: str) -> None:
    result = LibyaraCompiler().compile_file(filepath)

    assert result.success is False
    assert result.errors == ["filepath must not be empty"]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
@pytest.mark.parametrize("filepath", [None, False, 123, object(), b"rule.yar"])
def test_libyara_compiler_compile_file_rejects_invalid_filepath_types(filepath: Any) -> None:
    result = LibyaraCompiler().compile_file(cast(Any, filepath))

    assert result.success is False
    assert result.errors == ["filepath must be a string or path-like object"]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_file_rejects_inaccessible_filepath() -> None:
    result = LibyaraCompiler().compile_file("a" * 5000)

    assert result.success is False
    assert result.errors
    assert result.errors[0].startswith("path could not be accessed")


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_file_rejects_invalid_utf8(tmp_path: Path) -> None:
    rule_path = tmp_path / "invalid.yar"
    rule_path.write_bytes(b"\xff")

    result = LibyaraCompiler().compile_file(rule_path)

    assert result.success is False
    assert result.errors == ["YARA file must contain valid UTF-8 text"]
