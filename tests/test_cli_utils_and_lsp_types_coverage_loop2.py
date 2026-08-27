# Copyright (c) 2026 Marc Rivero López
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting remaining uncovered CLI utility lines.

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

"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

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
        utils.write_text(target, cast(Any, 42))


def test_write_text_raises_type_error_for_none_content(tmp_path: Path) -> None:
    """Lines 139-140: passing None as content raises TypeError."""
    target = tmp_path / "out.txt"
    target.write_text("placeholder", encoding="utf-8")
    with pytest.raises(TypeError, match="content must be a string"):
        utils.write_text(target, cast(Any, None))


def test_write_text_raises_type_error_for_bytes_content(tmp_path: Path) -> None:
    """Lines 139-140: bytes are not str -> TypeError."""
    target = tmp_path / "out.txt"
    target.write_text("placeholder", encoding="utf-8")
    with pytest.raises(TypeError, match="content must be a string"):
        utils.write_text(target, cast(Any, b"bytes content"))


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
    reason="corpus/conformance/structure.yar not present; docs/test-skips.yml",
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
    reason="corpus/conformance/structure.yar not present; docs/test-skips.yml",
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
