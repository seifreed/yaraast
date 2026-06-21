# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting remaining uncovered lines in two modules.

Targets
-------
yaraast/cli/utils.py
  - Lines 71-72  : _require_file_path bool/non-string TypeError branch
  - Lines 78-79  : _require_file_path whitespace-only ValueError branch
  - Lines 94-96  : _path_is_dir OSError branch (ENAMETOOLONG via direct call)
  - Lines 102-104: _path_is_file OSError branch (ENAMETOOLONG via direct call)
  - Lines 121-124: _require_existing_file_path directory ValueError branch
  - Lines 132-133: read_text UnicodeDecodeError -> ValueError branch
  - Lines 139-140: write_text non-string TypeError branch
  - Lines 143-145: write_text UnicodeEncodeError (lone surrogate) -> ValueError
  - Line  151    : write_json body (delegates to write_text)
  - Lines 174-176: parse_yara_file body (reads and parses real YARA source)

yaraast/lsp/lsp_types.py
  - Line 99: sys.path.remove(path) — the removal branch inside the fallback
              for-loop, reached when site-packages IS still in sys.path at the
              time the except ImportError block executes.  Triggered by injecting
              a synthetic broken lsprotocol.types package earlier in sys.path so
              that the primary import fails with exc.name == 'lsprotocol.types'
              while leaving the real site-packages entry untouched.

Unreachable lines (documented, not tested)
------------------------------------------
yaraast/cli/utils.py lines 94-96 / 102-104 via the composite helpers
  _path_exists_and_is_dir / _path_exists_and_is_file / _path_exists_and_not_dir:
  All three call _path_exists() first; path.exists() uses the same os.stat()
  syscall as path.is_dir() and path.is_file().  Any ENAMETOOLONG condition that
  would trigger OSError in is_dir()/is_file() also triggers it in exists(), so
  _path_exists() raises ValueError before _path_is_dir()/_path_is_file() are
  reached.  The OSError branches inside those helpers are therefore unreachable
  through the composite helpers.  They ARE reachable via direct calls, which is
  what lines 94-96 and 102-104 tests below exercise.

yaraast/lsp/lsp_types.py line 92 (re-raise branch):
  The containing try-block imports exclusively from lsprotocol.types; any
  ImportError it raises carries exc.name == 'lsprotocol' or 'lsprotocol.types',
  both of which are in _LSPROTOCOL_TYPES_IMPORT_NAMES, so
  _is_missing_lsprotocol_types(exc) always returns True and the guard evaluates
  to False (no re-raise).  No real execution path can set exc.name to an
  unrelated value inside that try-block; the branch is structurally dead code.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import shutil
import site
import sys
import tempfile
from types import ModuleType

import pytest

from yaraast.cli import utils

# ---------------------------------------------------------------------------
# _require_file_path — lines 71-72 (bool / non-str-non-PathLike TypeError)
# ---------------------------------------------------------------------------


def test_require_file_path_rejects_bool_true() -> None:
    """Line 71-72: bool True is explicitly excluded from the isinstance guard."""
    with pytest.raises(TypeError, match="path must be a file path"):
        utils._require_file_path(True)


def test_require_file_path_rejects_bool_false() -> None:
    """Line 71-72: bool False is excluded via the leading bool check."""
    with pytest.raises(TypeError, match="path must be a file path"):
        utils._require_file_path(False)


def test_require_file_path_rejects_integer() -> None:
    """Lines 71-72: an integer is neither str nor PathLike -> TypeError."""
    with pytest.raises(TypeError, match="path must be a file path"):
        utils._require_file_path(42)


def test_require_file_path_rejects_none() -> None:
    """Lines 71-72: None is neither str nor PathLike -> TypeError."""
    with pytest.raises(TypeError, match="path must be a file path"):
        utils._require_file_path(None)


# ---------------------------------------------------------------------------
# _require_file_path — lines 78-79 (empty / whitespace-only ValueError)
# ---------------------------------------------------------------------------


def test_require_file_path_rejects_empty_string() -> None:
    """Lines 78-79: empty string has strip() == '' -> ValueError."""
    with pytest.raises(ValueError, match="path must not be empty"):
        utils._require_file_path("")


def test_require_file_path_rejects_whitespace_only_string() -> None:
    """Lines 78-79: whitespace-only string also fails the strip() guard."""
    with pytest.raises(ValueError, match="path must not be empty"):
        utils._require_file_path("   ")


def test_require_file_path_rejects_tab_only_string() -> None:
    """Lines 78-79: a tab-only string is considered empty after stripping."""
    with pytest.raises(ValueError, match="path must not be empty"):
        utils._require_file_path("\t\n")


# ---------------------------------------------------------------------------
# _path_is_dir — lines 94-96 (OSError via ENAMETOOLONG, direct call)
# ---------------------------------------------------------------------------


def test_path_is_dir_oserror_converted_to_value_error() -> None:
    """Lines 94-96: ENAMETOOLONG from is_dir() is caught and re-raised as ValueError.

    A 5000-character path exceeds the kernel ENAMETOOLONG limit on macOS and
    Linux, causing Path.is_dir() to raise OSError.  _path_is_dir() is called
    directly here (not via _path_exists_and_is_dir) because path.exists() would
    also raise first when routed through the composite helper.
    """
    oversized = Path("d" * 5000)
    with pytest.raises(ValueError, match="path could not be accessed"):
        utils._path_is_dir(oversized)


# ---------------------------------------------------------------------------
# _path_is_file — lines 102-104 (OSError via ENAMETOOLONG, direct call)
# ---------------------------------------------------------------------------


def test_path_is_file_oserror_converted_to_value_error() -> None:
    """Lines 102-104: ENAMETOOLONG from is_file() is caught and re-raised as ValueError.

    Same rationale as test_path_is_dir_oserror_converted_to_value_error:
    _path_is_file() is called directly so the OSError branch is exercised
    without the composite helper intercepting via _path_exists().
    """
    oversized = Path("f" * 5000)
    with pytest.raises(ValueError, match="path could not be accessed"):
        utils._path_is_file(oversized)


# ---------------------------------------------------------------------------
# _require_existing_file_path — lines 121-124 (directory -> ValueError)
# ---------------------------------------------------------------------------


def test_require_existing_file_path_rejects_existing_directory(tmp_path: Path) -> None:
    """Lines 121-124: an existing directory raises ValueError."""
    with pytest.raises(ValueError, match="path must not be a directory"):
        utils._require_existing_file_path(tmp_path)


def test_require_existing_file_path_accepts_existing_file(tmp_path: Path) -> None:
    """Line 124: return path — an existing regular file is accepted."""
    real_file = tmp_path / "sample.txt"
    real_file.write_text("data", encoding="utf-8")
    result = utils._require_existing_file_path(real_file)
    assert result == real_file


# ---------------------------------------------------------------------------
# read_text — lines 132-133 (UnicodeDecodeError -> ValueError)
# ---------------------------------------------------------------------------


def test_read_text_raises_value_error_for_non_utf8_file(tmp_path: Path) -> None:
    """Lines 132-133: a binary file with invalid UTF-8 raises ValueError.

    The bytes 0xFF 0xFE are a Windows BOM for UTF-16 LE and are not valid
    UTF-8; reading them with errors='strict' (the default) raises UnicodeDecodeError
    which the function converts to ValueError.
    """
    binary_file = tmp_path / "binary.bin"
    binary_file.write_bytes(b"\xff\xfe\x80\x81\x82\x83")
    with pytest.raises(ValueError, match="file must contain valid UTF-8 text"):
        utils.read_text(binary_file)


def test_read_text_accepts_valid_utf8_file(tmp_path: Path) -> None:
    """Positive case: a valid UTF-8 file is returned as a str."""
    utf8_file = tmp_path / "hello.txt"
    utf8_file.write_text("hello world", encoding="utf-8")
    result = utils.read_text(utf8_file)
    assert result == "hello world"


# ---------------------------------------------------------------------------
# write_text — lines 139-140 (non-string TypeError)
# ---------------------------------------------------------------------------


def test_write_text_raises_type_error_for_integer_content(tmp_path: Path) -> None:
    """Lines 139-140: passing an integer as content raises TypeError."""
    target = tmp_path / "out.txt"
    target.write_text("placeholder", encoding="utf-8")
    with pytest.raises(TypeError, match="content must be a string"):
        utils.write_text(target, 42)  # type: ignore[arg-type]


def test_write_text_raises_type_error_for_none_content(tmp_path: Path) -> None:
    """Lines 139-140: passing None as content raises TypeError."""
    target = tmp_path / "out.txt"
    target.write_text("placeholder", encoding="utf-8")
    with pytest.raises(TypeError, match="content must be a string"):
        utils.write_text(target, None)  # type: ignore[arg-type]


def test_write_text_raises_type_error_for_bytes_content(tmp_path: Path) -> None:
    """Lines 139-140: bytes are not str -> TypeError."""
    target = tmp_path / "out.txt"
    target.write_text("placeholder", encoding="utf-8")
    with pytest.raises(TypeError, match="content must be a string"):
        utils.write_text(target, b"bytes content")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# write_text — lines 143-145 (UnicodeEncodeError -> ValueError via lone surrogate)
# ---------------------------------------------------------------------------


def test_write_text_raises_value_error_for_lone_surrogate(tmp_path: Path) -> None:
    """Lines 143-145: a Python str containing a lone surrogate fails UTF-8 encoding.

    Python strings use UCS-4/UTF-32 internally and can hold lone surrogate
    code points (U+D800..U+DFFF) that are not valid in UTF-8.  Calling
    str.encode('utf-8') on such a string raises UnicodeEncodeError, which
    write_text converts to ValueError.
    """
    target = tmp_path / "out.txt"
    target.write_text("placeholder", encoding="utf-8")
    surrogate_string = "\ud800"
    with pytest.raises(ValueError, match="content must be UTF-8 encodable"):
        utils.write_text(target, surrogate_string)


def test_write_text_raises_value_error_for_trailing_surrogate(tmp_path: Path) -> None:
    """Lines 143-145: trailing surrogate U+DFFF also fails UTF-8 encoding."""
    target = tmp_path / "out.txt"
    target.write_text("placeholder", encoding="utf-8")
    with pytest.raises(ValueError, match="content must be UTF-8 encodable"):
        utils.write_text(target, "\udfff")


# ---------------------------------------------------------------------------
# write_json — line 151 (body executed via successful write path)
# ---------------------------------------------------------------------------


def test_write_json_writes_serialized_json_to_existing_file(tmp_path: Path) -> None:
    """Line 151: write_json serializes data and delegates to write_text."""
    target = tmp_path / "output.json"
    target.write_text("{}", encoding="utf-8")  # must exist for write_text
    data = {"key": "value", "number": 42}
    utils.write_json(target, data)
    raw = target.read_text(encoding="utf-8")
    import json

    parsed = json.loads(raw)
    assert parsed == data


def test_write_json_uses_default_indent_of_two(tmp_path: Path) -> None:
    """Line 151: default indent=2 produces human-readable output."""
    target = tmp_path / "out.json"
    target.write_text("{}", encoding="utf-8")
    utils.write_json(target, {"x": 1})
    content = target.read_text(encoding="utf-8")
    assert '  "x": 1' in content


def test_write_json_accepts_custom_indent(tmp_path: Path) -> None:
    """Line 151: write_json passes the indent argument through to json.dumps."""
    target = tmp_path / "compact.json"
    target.write_text("{}", encoding="utf-8")
    utils.write_json(target, [1, 2, 3], indent=4)
    content = target.read_text(encoding="utf-8")
    assert "    1" in content


# ---------------------------------------------------------------------------
# parse_yara_file — lines 174-176 (import + parse real YARA source)
# ---------------------------------------------------------------------------

_CORPUS_STRUCTURE = Path(__file__).parent / "corpus" / "conformance" / "structure.yar"


@pytest.mark.skipif(
    not _CORPUS_STRUCTURE.exists(),
    reason="corpus/conformance/structure.yar not present",
)
def test_parse_yara_file_returns_yara_file_instance() -> None:
    """Lines 174-176: parse_yara_file reads + parses real YARA source from disk.

    The corpus fixture is a checked-in YARA file; parsing it exercises the
    full read_text -> parse_yara_source production pipeline.
    """
    from yaraast.ast.base import YaraFile

    result = utils.parse_yara_file(_CORPUS_STRUCTURE)
    assert isinstance(result, YaraFile)


@pytest.mark.skipif(
    not _CORPUS_STRUCTURE.exists(),
    reason="corpus/conformance/structure.yar not present",
)
def test_parse_yara_file_produces_non_empty_rule_list() -> None:
    """Lines 174-176: the parsed corpus file contains at least one rule."""
    result = utils.parse_yara_file(_CORPUS_STRUCTURE)
    assert hasattr(result, "rules")
    assert len(result.rules) > 0


def test_parse_yara_file_from_tmp_file(tmp_path: Path) -> None:
    """Lines 174-176: write a minimal YARA rule to a temp file and parse it."""
    from yaraast.ast.base import YaraFile

    yara_source = "rule minimal { condition: true }"
    yara_file = tmp_path / "minimal.yar"
    yara_file.write_text(yara_source, encoding="utf-8")

    result = utils.parse_yara_file(yara_file)
    assert isinstance(result, YaraFile)


# ---------------------------------------------------------------------------
# lsp_types — line 99: sys.path.remove(path) inside fallback for-loop
# ---------------------------------------------------------------------------


def _make_broken_lsprotocol_package(directory: str) -> None:
    """Create a synthetic lsprotocol package under *directory*.

    The package __init__.py is empty (import succeeds), but types.py raises
    ImportError with exc.name set to 'lsprotocol.types'.  When this directory
    is prepended to sys.path before importing lsprotocol.types, the primary
    import in lsp_types.py fails with the correct exc.name, triggering the
    fallback block while leaving the real site-packages entry still in sys.path.

    Inside the fallback block, the for-loop over reversed(site.getsitepackages())
    then finds the real site-packages IS in sys.path and calls sys.path.remove()
    (line 99), which is the branch this test suite targets.
    """
    pkg_dir = os.path.join(directory, "lsprotocol")
    os.makedirs(pkg_dir, exist_ok=True)
    with open(os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8") as fh:
        fh.write("")
    with open(os.path.join(pkg_dir, "types.py"), "w", encoding="utf-8") as fh:
        fh.write(
            'e = ImportError("No module named lsprotocol.types")\n'
            'e.name = "lsprotocol.types"\n'
            "raise e\n"
        )


def _pop_lsprotocol_modules() -> dict[str, ModuleType]:
    """Remove all lsprotocol-related entries from sys.modules and return them."""
    removed: dict[str, ModuleType] = {}
    for key in list(sys.modules.keys()):
        if "lsprotocol" in key:
            removed[key] = sys.modules.pop(key)
    return removed


class TestLspTypesLine99RemovePath:
    """Exercise the sys.path.remove(path) branch (line 99) in lsp_types.py.

    The existing test suite in test_lsp_types_coverage_loop.py reaches the
    fallback block by removing site-packages from sys.path *before* the import.
    That means when the fallback block's for-loop runs and checks
    ``if path in sys.path``, the path is already absent, so sys.path.remove
    (line 99) is never called.

    This test class takes the alternative approach: inject a broken
    lsprotocol.types earlier in sys.path while leaving the real site-packages
    entry intact, so that:
      1. The primary import raises ImportError with exc.name == 'lsprotocol.types'.
      2. The fallback for-loop finds site-packages IS in sys.path.
      3. sys.path.remove(path) on line 99 executes, then line 100 re-inserts it.
    """

    @staticmethod
    def _trigger_with_broken_package() -> ModuleType:
        """Inject a broken lsprotocol package and re-import lsp_types.

        Returns the freshly-loaded module.  Restores sys.path and sys.modules
        fully before returning so subsequent tests are not affected.
        """
        site_packages = site.getsitepackages()
        real_sp_in_path = [sp for sp in site_packages if sp in sys.path]
        if not real_sp_in_path:
            pytest.skip("Real site-packages not found in sys.path — cannot trigger line 99")

        tmpdir = tempfile.mkdtemp()
        try:
            _make_broken_lsprotocol_package(tmpdir)

            # Save state before mutation.
            saved_path = sys.path[:]
            saved_lsprotocol = _pop_lsprotocol_modules()
            saved_lsp_types = sys.modules.pop("yaraast.lsp.lsp_types", None)
            lsp_parent = sys.modules.get("yaraast.lsp")
            parent_attr_before = (
                lsp_parent.__dict__.get("lsp_types") if lsp_parent is not None else None
            )

            # Prepend the broken package directory BEFORE real site-packages.
            # Site-packages remains in sys.path so line 99 will be hit.
            sys.path.insert(0, tmpdir)

            recovered: ModuleType
            try:
                recovered = importlib.import_module("yaraast.lsp.lsp_types")
            finally:
                # Remove the freshly-created module entry so the restored
                # original object becomes authoritative.
                sys.modules.pop("yaraast.lsp.lsp_types", None)
                # Remove the injected broken lsprotocol if it leaked.
                for key in list(sys.modules.keys()):
                    if "lsprotocol" in key:
                        sys.modules.pop(key, None)
                # Restore sys.path.
                sys.path[:] = saved_path
                # Restore original lsprotocol modules.
                sys.modules.update(saved_lsprotocol)
                # Restore original lsp_types module.
                if saved_lsp_types is not None:
                    sys.modules["yaraast.lsp.lsp_types"] = saved_lsp_types
                # Restore parent package attribute.
                if lsp_parent is not None:
                    if parent_attr_before is not None:
                        lsp_parent.__dict__["lsp_types"] = parent_attr_before
                    else:
                        lsp_parent.__dict__.pop("lsp_types", None)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return recovered

    def test_fallback_line99_module_loads_successfully(self) -> None:
        """Line 99 hit: sys.path.remove removes real site-packages, then re-inserts it.

        The module must still load successfully because after removing and
        re-inserting the site-packages entry at position 0, importlib finds
        the real lsprotocol.types there and completes the import.
        """
        recovered = self._trigger_with_broken_package()
        assert hasattr(recovered, "YARAAST_RUNTIME_STATUS")
        assert recovered.YARAAST_RUNTIME_STATUS == "yaraast/status"

    def test_fallback_line99_range_class_is_real_type(self) -> None:
        """After line 99 path, Range must be the real lsprotocol.types class."""
        recovered = self._trigger_with_broken_package()
        range_cls = recovered.Range
        assert isinstance(range_cls, type)
        assert "lsprotocol" in range_cls.__module__

    def test_fallback_line99_all_members_present(self) -> None:
        """All __all__ names must be present on the recovered module."""
        import yaraast.lsp.lsp_types as stable

        expected = list(stable.__all__)
        recovered = self._trigger_with_broken_package()
        for name in expected:
            assert hasattr(recovered, name), f"Missing after line-99 path: {name!r}"

    def test_fallback_line99_sys_path_restored(self) -> None:
        """Ensure the helper fully restores sys.path after exercising line 99."""
        original_path = sys.path[:]
        self._trigger_with_broken_package()
        assert sys.path == original_path, "sys.path was not fully restored after test"
