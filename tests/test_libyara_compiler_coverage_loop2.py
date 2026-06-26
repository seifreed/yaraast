# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting remaining uncovered lines in yaraast/libyara/compiler.py.

Missing lines after test_libyara_compiler_coverage_loop.py (confirmed via
--cov-report=term-missing): 330-333.

Lines 330-331 (except (TypeError, ValueError)) and 332-335 (except Exception) in
compile_file ARE reachable via real production inputs:

  * Line 330-331: normalize_libyara_includes raises TypeError when includes has a
    non-string key, and raises ValueError when includes has an empty-string key.
    Both occur inside the try block that wraps the entire compile_file compilation
    phase, and neither is caught earlier than line 330.

    Additionally, yara.compile raises a plain TypeError (not a yara.Error subclass)
    when error_on_warning receives a non-bool argument.  compile_file builds
    compile_kwargs directly—unlike compile_source, it does not call
    require_error_on_warning before the yara.compile call—so that TypeError reaches
    line 330 through a different input vector.

  * Line 332-335: normalize_libyara_includes calls dict.items() on its argument.
    A dict subclass that overrides items() to raise RuntimeError will propagate a
    RuntimeError through normalize_libyara_includes into the compile_file try block,
    where it is not a yara.Error, TypeError, or ValueError, and is therefore caught
    by the generic except Exception clause at line 332.  RuntimeError is a real
    Python exception type—no injection, no patching of the module under test.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE, LibyaraCompiler

if not YARA_AVAILABLE:
    pytest.skip("yara-python not available", allow_module_level=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_rule_file(tmp_path: Path) -> Path:
    """Write a syntactically valid YARA rule to a temporary file."""
    rule_file = tmp_path / "valid.yar"
    rule_file.write_text("rule always_true { condition: true }\n", encoding="utf-8")
    return rule_file


class _ItemsRaisingDict(dict):  # type: ignore[type-arg]
    """dict subclass whose items() raises RuntimeError.

    Used to trigger the generic except Exception clause in compile_file (lines
    332-335).  normalize_libyara_includes calls .items() on its argument, so
    passing an instance of this class as the includes argument causes a
    RuntimeError that is not a yara.Error, TypeError, or ValueError.
    """

    def items(self) -> Any:
        msg = "items() deliberately raised for testing except Exception branch"
        raise RuntimeError(msg)


# ---------------------------------------------------------------------------
# compile_file — except (TypeError, ValueError): lines 330-331
# via normalize_libyara_includes raising TypeError on a non-string includes key
# ---------------------------------------------------------------------------


def test_compile_file_includes_non_string_key_hits_type_error_branch(
    tmp_path: Path,
) -> None:
    """Lines 330-331: compile_file catches TypeError from normalize_libyara_includes.

    normalize_libyara_includes raises TypeError when a key in the includes dict is
    not a string.  That TypeError is raised inside the try block that wraps the
    compilation phase of compile_file and is caught by the
    `except (TypeError, ValueError)` clause at line 330.

    The error message must be the raw exception text without the "Syntax error:" or
    "Compilation error:" prefixes added by the yara-specific except branches, and
    source_code must be set because the file was read successfully before the error.
    """
    compiler = LibyaraCompiler()
    rule_file = _valid_rule_file(tmp_path)
    # Integer key is not a string: normalize_libyara_includes raises TypeError.
    bad_includes: dict[Any, Any] = {123: "rule helper { condition: true }\n"}

    result = compiler.compile_file(rule_file, includes=bad_includes)

    assert result.success is False
    assert result.errors
    assert "libyara include names must be strings" in result.errors[0]
    assert not result.errors[0].startswith("Syntax error:")
    assert not result.errors[0].startswith("Compilation error:")
    assert not result.errors[0].startswith("Unexpected error:")
    assert result.source_code is not None


# ---------------------------------------------------------------------------
# compile_file — except (TypeError, ValueError): lines 330-331
# via normalize_libyara_includes raising ValueError on an empty-string includes key
# ---------------------------------------------------------------------------


def test_compile_file_includes_empty_string_key_hits_value_error_branch(
    tmp_path: Path,
) -> None:
    """Lines 330-331: compile_file catches ValueError from normalize_libyara_includes.

    normalize_libyara_includes raises ValueError when a key in the includes dict is
    an empty or whitespace-only string.  That ValueError is raised inside the
    compilation try block and is caught by the `except (TypeError, ValueError)` clause.
    """
    compiler = LibyaraCompiler()
    rule_file = _valid_rule_file(tmp_path)
    # Empty string key: normalize_libyara_includes raises ValueError.
    bad_includes: dict[str, str] = {"": "rule helper { condition: true }\n"}

    result = compiler.compile_file(rule_file, includes=bad_includes)

    assert result.success is False
    assert result.errors
    assert "libyara include names must not be empty" in result.errors[0]
    assert not result.errors[0].startswith("Syntax error:")
    assert not result.errors[0].startswith("Compilation error:")
    assert not result.errors[0].startswith("Unexpected error:")
    assert result.source_code is not None


# ---------------------------------------------------------------------------
# compile_file — except (TypeError, ValueError): lines 330-331
# via normalize_libyara_includes raising TypeError on a non-string includes value
# ---------------------------------------------------------------------------


def test_compile_file_includes_non_string_value_hits_type_error_branch(
    tmp_path: Path,
) -> None:
    """Lines 330-331: compile_file catches TypeError when includes value is non-string.

    normalize_libyara_includes raises TypeError when a value in the includes dict is
    not a string.  This variant exercises the third validation path inside
    normalize_libyara_includes (content type check) and confirms line 330 is reachable
    from multiple normalization failures.
    """
    compiler = LibyaraCompiler()
    rule_file = _valid_rule_file(tmp_path)
    # Integer value instead of string: normalize_libyara_includes raises TypeError.
    bad_includes: dict[Any, Any] = {"helper.yar": 99}

    result = compiler.compile_file(rule_file, includes=bad_includes)

    assert result.success is False
    assert result.errors
    assert "libyara include contents must be strings" in result.errors[0]
    assert not result.errors[0].startswith("Unexpected error:")
    assert result.source_code is not None


# ---------------------------------------------------------------------------
# compile_file — except (TypeError, ValueError): lines 330-331
# via yara.compile raising plain TypeError on non-bool error_on_warning
# ---------------------------------------------------------------------------


def test_compile_file_non_bool_error_on_warning_hits_type_error_branch(
    tmp_path: Path,
) -> None:
    """Lines 330-331: compile_file catches TypeError raised by yara.compile.

    compile_file constructs compile_kwargs directly without calling
    require_error_on_warning, so a non-bool error_on_warning value is forwarded to
    yara.compile unchanged.  yara.compile raises a plain TypeError (not a yara.Error
    subclass) when it receives a non-bool for error_on_warning.  That TypeError reaches
    the `except (TypeError, ValueError)` clause at line 330 through a different code
    path than the normalize_libyara_includes-raised TypeError above.

    This demonstrates that line 330 defends against both normalization failures and
    unexpected type mismatches from the underlying yara-python C extension.
    """
    compiler = LibyaraCompiler()
    rule_file = _valid_rule_file(tmp_path)

    # Pass a string where bool is required; yara.compile will raise TypeError.
    result = compiler.compile_file(rule_file, error_on_warning="yes")  # type: ignore[arg-type]

    assert result.success is False
    assert result.errors
    # yara-python's TypeError message does not carry a "Syntax error:" or
    # "Compilation error:" prefix; it arrives undecorated via line 331.
    assert not result.errors[0].startswith("Syntax error:")
    assert not result.errors[0].startswith("Compilation error:")
    assert not result.errors[0].startswith("Unexpected error:")
    assert result.source_code is not None


# ---------------------------------------------------------------------------
# compile_file — except Exception: lines 332-335
# via dict subclass whose items() raises RuntimeError
# ---------------------------------------------------------------------------


def test_compile_file_includes_items_raise_hits_generic_except_branch(
    tmp_path: Path,
) -> None:
    """Lines 332-335: compile_file catches generic Exception from a misbehaving dict.

    normalize_libyara_includes calls .items() on its argument.  Passing a dict
    subclass whose items() raises RuntimeError causes that RuntimeError to propagate
    out of normalize_libyara_includes into the compile_file try block.  RuntimeError
    is not a yara.SyntaxError, yara.Error, TypeError, or ValueError, so it falls
    through to the `except Exception` clause at line 332.

    No module patching or monkeypatching is used; _ItemsRaisingDict is a plain Python
    dict subclass that exercises the generic safety net in compile_file.
    """
    compiler = LibyaraCompiler()
    rule_file = _valid_rule_file(tmp_path)
    # The dict passes the `includes is not None` guard and reaches normalize_libyara_includes.
    bad_includes = _ItemsRaisingDict({"helper.yar": "rule h { condition: true }\n"})

    result = compiler.compile_file(rule_file, includes=bad_includes)

    assert result.success is False
    assert result.errors
    assert result.errors[0].startswith("Unexpected error:")
    assert "items() deliberately raised" in result.errors[0]
    assert result.source_code is not None
