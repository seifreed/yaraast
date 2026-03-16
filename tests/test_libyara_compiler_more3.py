from __future__ import annotations

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE, LibyaraCompiler


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_handles_read_and_save_failures(tmp_path) -> None:
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

    type_error_result = compiler.compile_source(None)  # type: ignore[arg-type]
    assert type_error_result.success is False
    assert type_error_result.errors
    assert "Unexpected error" in type_error_result.errors[0]

    null_byte_result = compiler.compile_source(
        'rule bad {\nstrings:\n$a = "a\x00b"\ncondition:\n$a\n}\n'
    )
    assert null_byte_result.source_code is not None
