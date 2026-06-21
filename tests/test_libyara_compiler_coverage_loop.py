# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting the uncovered lines in yaraast/libyara/compiler.py.

Missing lines confirmed via --cov-report=term-missing before this file was added:
  18-22   - module-level ImportError guard (yara = None / YARA_AVAILABLE = False)
  56      - normalize_libyara_includes returns None when called with None directly
  105-106 - LibyaraCompiler.__init__ raises ImportError when YARA_AVAILABLE is False
  196     - except yara.Error in compile_source (WarningError from slow-regex warning)
  284     - "File not found" branch in compile_file
  322-329 - except yara.SyntaxError and except yara.Error branches in compile_file

Lines 245-246 and 310 are dead code: _compile_kwargs and compile_file both guard
`includes is None` before calling normalize_libyara_includes, which is the only code
path that can return None; so the subsequent `if normalized_includes is None` branch
can never be reached through the public API.

Lines 330-335 (except (TypeError, ValueError) and except Exception in compile_file)
are structurally unreachable: LibyaraCompiler validates externals at construction time
via normalize_libyara_externals, so yara.compile cannot receive unsupported external
types, and no other normal operation produces these exception types from yara.compile.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest

from yaraast.libyara.compiler import (
    YARA_AVAILABLE,
    LibyaraCompiler,
    normalize_libyara_includes,
)

# ---------------------------------------------------------------------------
# normalize_libyara_includes - line 56 (return None when argument is None)
# ---------------------------------------------------------------------------


def test_normalize_libyara_includes_returns_none_for_none_argument() -> None:
    """Calling normalize_libyara_includes(None) must return None (line 56)."""
    result = normalize_libyara_includes(None)
    assert result is None


# ---------------------------------------------------------------------------
# Module-level import guard and constructor guard (lines 18-22 and 105-106)
# ---------------------------------------------------------------------------


def test_module_level_yara_none_and_constructor_importerror_when_yara_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lines 18-22 and 105-106: reload compiler with yara blocked at import level.

    The real import interception forces the module-level try/except to take the
    `except ImportError` branch (is_missing_yara_import returns True for name=='yara'),
    setting `yara = None` and `YARA_AVAILABLE = False`.  Constructing LibyaraCompiler
    from the reloaded module then exercises the `if not YARA_AVAILABLE: raise ImportError`
    guard.  The module is fully restored after the test.
    """
    import builtins

    import yaraast.libyara.compiler as compiler_module

    real_import = builtins.__import__

    def _block_yara_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "yara":
            raise ImportError("blocked for test", name="yara")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_yara_import)
    importlib.reload(compiler_module)

    # Lines 18-22 executed by the reload above.
    assert compiler_module.YARA_AVAILABLE is False
    # Access the module-level `yara` name via vars() because mypy does not see it
    # in the module's explicit exports.
    assert vars(compiler_module)["yara"] is None

    # Lines 105-106: the constructor must reject instantiation.
    with pytest.raises(ImportError, match="yara-python is not installed"):
        compiler_module.LibyaraCompiler()

    # monkeypatch restores builtins.__import__ automatically at teardown.
    # Reload once more so that subsequent tests in the same worker see a clean module.
    monkeypatch.undo()
    importlib.reload(compiler_module)
    assert compiler_module.YARA_AVAILABLE is True
    assert vars(compiler_module)["yara"] is not None


# ---------------------------------------------------------------------------
# Module-level import guard - line 20 (re-raise non-yara ImportError)
# ---------------------------------------------------------------------------


def test_module_level_reraises_importerror_for_non_yara_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Line 20: the module re-raises ImportError when the failing import is not 'yara'.

    When an ImportError occurs during `import yara` but the error's `.name` attribute
    is not 'yara' (indicating a broken sub-dependency, not a missing optional module),
    `is_missing_yara_import` returns False, and the `raise` on line 20 propagates the
    exception rather than silencing it.

    Coverage of line 20 is unreliable under pytest-xdist because importlib.reload
    executes in a worker subprocess whose coverage data fails to combine due to a
    schema mismatch in the coverage SQLite backend.  This test verifies the behavior
    is correct by observing that the reload raises the original ImportError.
    """
    import builtins

    import yaraast.libyara.compiler as compiler_module

    real_import = builtins.__import__
    original_error = ImportError("broken sub-dep", name="yara._native")

    def _raise_sub_dep_error(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "yara":
            raise original_error
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _raise_sub_dep_error)
    with pytest.raises(ImportError, match="broken sub-dep"):
        importlib.reload(compiler_module)

    # monkeypatch restores builtins.__import__ automatically; reload to clean up.
    monkeypatch.undo()
    importlib.reload(compiler_module)
    assert compiler_module.YARA_AVAILABLE is True


# ---------------------------------------------------------------------------
# compile_source - except yara.Error branch (line 196)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_compile_source_catches_yara_warning_error_as_compilation_error() -> None:
    """Line 196: yara.WarningError (a yara.Error subclass) is caught as a compilation error.

    A YARA regex containing `.*` triggers a WarningError when error_on_warning=True.
    The except yara.Error branch (not the SyntaxError branch) must handle it, producing
    a CompilationResult with success=False and an error starting with "Compilation error:".
    """
    compiler = LibyaraCompiler()
    # The .*abc regex generates a yara warning about unbounded wildcards.
    source = "rule warn_test { strings: $s = /.*abc/ condition: $s }"

    result = compiler.compile_source(source, error_on_warning=True)

    # Do not use isinstance here: importlib.reload in a sibling test can cause the
    # top-level CompilationResult reference to diverge from the one produced by
    # compile_source if both tests land on the same xdist worker.  The structural
    # attributes fully characterise the returned value.
    assert result.success is False
    assert result.errors
    assert result.errors[0].startswith("Compilation error:")
    assert result.source_code == source


# ---------------------------------------------------------------------------
# compile_file - "File not found" branch (line 284)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_compile_file_returns_failure_for_nonexistent_path(tmp_path: Path) -> None:
    """Line 284: compile_file reports failure when the file does not exist.

    A path whose parent directory exists but the file itself does not triggers the
    `if not file_exists` branch.  This is distinct from an inaccessible path (which
    raises OSError from path.exists()) or an empty path (rejected before the check).
    """
    compiler = LibyaraCompiler()
    missing = tmp_path / "does_not_exist.yar"

    result = compiler.compile_file(missing)

    assert result.success is False
    assert result.errors
    assert result.errors[0].startswith("File not found:")
    assert str(missing) in result.errors[0]


# ---------------------------------------------------------------------------
# compile_file - except yara.SyntaxError branch (lines 322-325)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_compile_file_catches_syntax_error_from_invalid_rule(tmp_path: Path) -> None:
    """Lines 322-325: compile_file catches yara.SyntaxError from a malformed rule file.

    Writing a YARA file with a missing condition body causes libyara to raise
    yara.SyntaxError during compilation.  The result must report failure with an
    error message that starts with "Syntax error:".
    """
    compiler = LibyaraCompiler()
    bad_rule = tmp_path / "bad.yar"
    bad_rule.write_text("rule bad { condition: }\n", encoding="utf-8")

    result = compiler.compile_file(bad_rule)

    assert result.success is False
    assert result.errors
    assert result.errors[0].startswith("Syntax error:")
    assert result.source_code == bad_rule.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# compile_file - except yara.Error branch (lines 326-329)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_compile_file_catches_yara_warning_error_as_compilation_error(tmp_path: Path) -> None:
    """Lines 326-329: compile_file catches yara.WarningError (a yara.Error subclass).

    A YARA regex with `.*` generates a warning; with error_on_warning=True this becomes
    a yara.WarningError.  The except yara.Error clause (distinct from SyntaxError) must
    handle it, producing success=False and an error starting with "Compilation error:".
    """
    compiler = LibyaraCompiler()
    warn_rule = tmp_path / "warn.yar"
    warn_rule.write_text(
        "rule warn_test { strings: $s = /.*abc/ condition: $s }\n",
        encoding="utf-8",
    )

    result = compiler.compile_file(warn_rule, error_on_warning=True)

    assert result.success is False
    assert result.errors
    assert result.errors[0].startswith("Compilation error:")
    assert result.source_code == warn_rule.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Dead-code documentation: lines that cannot be reached via the public API
# ---------------------------------------------------------------------------


def test_normalize_libyara_includes_none_result_is_only_reachable_with_none_arg() -> None:
    """Document that normalize_libyara_includes returns None only when passed None.

    Lines 244-246 in _compile_kwargs and line 310 in compile_file check whether
    normalize_libyara_includes returns None after calling it with a non-None argument.
    Because normalize_libyara_includes never returns None for non-None inputs (it raises
    on invalid inputs and returns a dict on valid ones), those branches are dead code
    within the current implementation and cannot be reached through the public API.
    """
    # None input -> None output (line 56).
    assert normalize_libyara_includes(None) is None

    # Non-None valid input -> non-None dict output.
    valid_result = normalize_libyara_includes({"header.yar": "rule h { condition: true }\n"})
    assert valid_result is not None
    assert valid_result == {"header.yar": "rule h { condition: true }\n"}

    # Invalid inputs raise TypeError or ValueError rather than returning None.
    # The argument is typed as Any to pass an invalid runtime type without a cast.
    bad_list: Any = []
    with pytest.raises(TypeError):
        normalize_libyara_includes(bad_list)

    with pytest.raises(ValueError):
        normalize_libyara_includes({"": "rule x { condition: true }\n"})
