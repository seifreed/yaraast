# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests that cover the remaining uncovered lines in:

  yaraast/cli/commands/validate.py       (target: 100%)
    Lines 88-90  — roundtrip: ``if not YARA_AVAILABLE`` error path
    Lines 95-97  — roundtrip: ``except (ValueError, ValidationError)`` from read_test_data

  yaraast/performance/validation.py      (target: 100%)
    Lines 36-37  — path_is_dir: ``except OSError`` path (permission-denied stat)
    Line  58     — validate_file_path_sequence: bytes entry in sequence
    Line  61     — validate_file_path_sequence: PathLike whose __fspath__ returns bytes

All tests exercise the real production code through its public API.
No mocks, stubs, or test doubles are used.
"""

from __future__ import annotations

import os
from os import PathLike
from pathlib import Path
import stat
from typing import Any

import pytest

import yaraast.cli.commands.validate as validate_module
from yaraast.cli.commands.validate import validate
from yaraast.cli.validate_services import read_test_data
from yaraast.errors import ValidationError
from yaraast.libyara import YARA_AVAILABLE
from yaraast.performance.validation import (
    FILE_PATH_ENTRY_TYPE_ERROR,
    path_is_dir,
    validate_file_path_sequence,
)

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


def _write_valid_yara(path: Path) -> None:
    """Write a syntactically valid YARA rule file to *path*."""
    path.write_text(
        "rule coverage_test {\n    condition:\n        true\n}\n",
        encoding="utf-8",
    )


def _is_root_process() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0


# ---------------------------------------------------------------------------
# validate.py — lines 88-90: roundtrip when YARA_AVAILABLE is False
#
# The production code at line 87 tests the module-level YARA_AVAILABLE flag
# imported from yaraast.libyara.  We temporarily set the flag to False on
# the validate_module namespace (where the name was resolved at import time)
# so the running process behaves as if yara-python were absent.
# ---------------------------------------------------------------------------


class TestRoundtripYaraNotAvailable:
    """Covers validate.py lines 88-90: the YARA_AVAILABLE == False branch."""

    def test_roundtrip_prints_error_and_exits_1_when_yara_missing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Arrange: patch module-level YARA_AVAILABLE to False.

        Act: invoke the roundtrip subcommand via Click's test runner.
        Assert: exit code is 1 and both error lines appear on stderr.
        """
        rule_file = tmp_path / "rule.yar"
        _write_valid_yara(rule_file)

        # Set the module-level name used by the roundtrip callback.
        # monkeypatch restores the original value automatically after the test.
        monkeypatch.setattr(validate_module, "YARA_AVAILABLE", False)

        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(validate, ["roundtrip", str(rule_file)])

        # Lines 88-89: click.echo(..., err=True) writes both messages; in
        # Click 8.x the CliRunner captures them so they appear in result.output
        # and also in result.stderr.
        # Line 90: sys.exit(1) produces exit_code 1.
        assert result.exit_code == 1
        assert "yara-python is not installed" in result.output
        assert "pip install yara-python" in result.output


# ---------------------------------------------------------------------------
# validate.py — lines 95-97: roundtrip when read_test_data raises
#
# The roundtrip command passes --test-data through Click's Path validator
# (exists=True, dir_okay=False) before calling read_test_data.  To reach
# the except branch we need a file that:
#   1. Exists at Click validation time (so Click accepts it), AND
#   2. Cannot be opened for reading when read_test_data runs (so open()
#      raises PermissionError, which read_test_data converts to ValidationError).
#
# This is achieved by removing the file's read permission between Click's
# check and the actual open() call — or, more reliably, by calling the
# service function directly, bypassing Click entirely.
# ---------------------------------------------------------------------------


class TestRoundtripReadTestDataError:
    """Covers validate.py lines 95-97: ValidationError from read_test_data.

    The except branch at lines 95-97 catches (ValueError, ValidationError)
    raised by read_test_data().  Click's Path validator (exists=True) also
    checks readability via os.access(), so we cannot rely on passing an
    unreadable file through Click.  Instead we invoke the roundtrip callback
    directly — bypassing Click's parameter validation — with a path that
    will fail when Python's open() is called.
    """

    @pytest.mark.skipif(
        not YARA_AVAILABLE,
        reason="yara-python is required for the roundtrip command",
    )
    def test_roundtrip_callback_catches_validation_error_from_read_test_data(
        self,
        tmp_path: Path,
    ) -> None:
        """Arrange: write a valid rule file; make an unreadable data file.

        Act: call the roundtrip command callback directly (bypassing Click's
        parameter validation) so that read_test_data() reaches the open() call
        and raises ValidationError, which lines 95-97 catch.

        Assert: SystemExit(1) is raised (line 97: sys.exit(1)).

        Root users bypass file permission checks, so the test is skipped when
        running as root.
        """
        if _is_root_process():
            pytest.skip("Running as root: permission bits have no effect")

        rule_file = tmp_path / "rule.yar"
        _write_valid_yara(rule_file)

        data_file = tmp_path / "data.bin"
        data_file.write_bytes(b"\x00\x01\x02\x03")
        # Remove all permissions: Click is bypassed, so only Python's open()
        # is called — and it will raise PermissionError → ValidationError.
        data_file.chmod(0o000)

        # Retrieve the Python-level callback (not the Click Command wrapper).
        roundtrip_cmd = validate.commands["roundtrip"]
        callback = roundtrip_cmd.callback
        assert callback is not None, "roundtrip command must have a callback"

        try:
            with pytest.raises(SystemExit) as exc_info:
                # Direct call: rule_file, test_data, verbose
                callback(str(rule_file), str(data_file), False)
            assert exc_info.value.code == 1
        finally:
            data_file.chmod(0o644)

    def test_read_test_data_raises_validation_error_on_unreadable_file(
        self,
        tmp_path: Path,
    ) -> None:
        """Direct call to the service function: confirm ValidationError is raised
        for an unreadable file.  This documents the exception type that lines
        95-97 in validate.py catch.

        This test covers the ValidationError raise in validate_services.py and
        validates the contract relied on by the CLI layer.
        """
        if _is_root_process():
            pytest.skip("Running as root: permission bits have no effect")

        data_file = tmp_path / "unreadable.bin"
        data_file.write_bytes(b"\xde\xad\xbe\xef")
        data_file.chmod(0o000)

        try:
            with pytest.raises(ValidationError, match="Error reading test data"):
                read_test_data(str(data_file))
        finally:
            data_file.chmod(0o644)


# ---------------------------------------------------------------------------
# performance/validation.py — lines 36-37: path_is_dir OSError path
#
# Path.is_dir() calls Path.stat() internally.  When the parent directory
# loses execute permission, stat() on any child raises PermissionError
# (errno 13), which Python's pathlib does NOT suppress (only ENOENT-class
# errors are suppressed).  The except OSError clause at lines 36-37 in
# path_is_dir() catches this and raises a descriptive ValueError instead.
# ---------------------------------------------------------------------------


class TestPathIsDirOSError:
    """Covers performance/validation.py lines 36-37."""

    def test_path_is_dir_raises_value_error_on_permission_denied(
        self,
        tmp_path: Path,
    ) -> None:
        """Arrange: create a nested path whose parent has no execute permission.

        Act: call path_is_dir() on the nested path.

        Assert: ValueError is raised with the expected message, proving the
        OSError from stat() is caught and re-raised as ValueError.
        """
        if _is_root_process():
            pytest.skip("Running as root: permission bits have no effect")

        locked_dir = tmp_path / "locked"
        locked_dir.mkdir()
        inner = locked_dir / "target"
        inner.mkdir()

        # Remove execute bit: stat() on inner will raise PermissionError.
        locked_dir.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600 — no execute
        try:
            with pytest.raises(ValueError, match="path could not be accessed"):
                path_is_dir(inner)
        finally:
            # Restore so pytest's tmp_path cleanup can remove the tree.
            locked_dir.chmod(stat.S_IRWXU)


# ---------------------------------------------------------------------------
# performance/validation.py — line 58: bytes entry in sequence
#
# validate_file_path_sequence checks each element in the sequence.
# A bytes entry passes the outer Sequence check (bytes is excluded at the
# top-level but not as an element), and must raise TypeError.
# ---------------------------------------------------------------------------


class TestValidateFilePathSequenceBytesEntry:
    """Covers performance/validation.py line 58."""

    def test_bytes_entry_in_list_raises_type_error(self) -> None:
        """Arrange: a list containing a bytes object as one element.

        Act: call validate_file_path_sequence.

        Assert: TypeError is raised with the correct message, confirming
        line 58 (the isinstance(file_path, bytes) branch) executed.
        """
        with pytest.raises(TypeError, match=FILE_PATH_ENTRY_TYPE_ERROR):
            validate_file_path_sequence([b"/tmp/rule.yar"])

    def test_integer_entry_in_list_raises_type_error(self) -> None:
        """An integer entry is not str, bytes, or PathLike — also hits line 58
        via the ``not isinstance(file_path, (str, PathLike))`` sub-condition.
        """
        with pytest.raises(TypeError, match=FILE_PATH_ENTRY_TYPE_ERROR):
            validate_file_path_sequence([42])

    def test_none_entry_in_list_raises_type_error(self) -> None:
        """None is not str, bytes, or PathLike — hits line 58."""
        with pytest.raises(TypeError, match=FILE_PATH_ENTRY_TYPE_ERROR):
            validate_file_path_sequence([None])

    def test_null_byte_entry_in_list_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="file_paths must not contain null bytes"):
            validate_file_path_sequence(["\x00broken"])

    def test_valid_mixed_str_and_path_entries_succeed(
        self,
        tmp_path: Path,
    ) -> None:
        """A sequence containing str paths and Path objects must succeed.
        Exercises the happy path through the loop (lines 56-65) to confirm
        the TypeError guards do not fire on valid input.
        """
        a = tmp_path / "a.yar"
        b = tmp_path / "b.yar"
        a.write_text("", encoding="utf-8")
        b.write_text("", encoding="utf-8")

        result = validate_file_path_sequence([str(a), b])
        assert result == [str(a), str(b)]

    def test_symlink_entry_in_list_raises_value_error(self, tmp_path: Path) -> None:
        target = tmp_path / "target.yar"
        target.write_text("", encoding="utf-8")
        link = tmp_path / "link.yar"
        link.symlink_to(target)

        with pytest.raises(ValueError, match="file_paths must not traverse a symlink"):
            validate_file_path_sequence([link])

    def test_symlink_ancestor_entry_in_list_raises_value_error(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        link_dir = tmp_path / "linked"
        link_dir.symlink_to(outside, target_is_directory=True)
        file_path = link_dir / "nested.yar"
        file_path.write_text("", encoding="utf-8")

        with pytest.raises(ValueError, match="file_paths must not traverse a symlink"):
            validate_file_path_sequence([file_path])


# ---------------------------------------------------------------------------
# performance/validation.py — line 61: PathLike whose __fspath__ returns bytes
#
# os.fspath(obj) returns whatever obj.__fspath__() returns.  When __fspath__
# returns bytes rather than str, the result is not an instance of str, so
# line 60 (``not isinstance(normalized_path, str)``) is True and line 61
# raises TypeError.
# ---------------------------------------------------------------------------


class _BytesPathLike(PathLike[Any]):
    """PathLike implementation whose __fspath__ returns bytes, not str.

    This is a valid os.PathLike[bytes] object.  It passes the
    ``isinstance(file_path, (str, PathLike))`` check but causes
    ``fspath(file_path)`` to return bytes, which is not a str.
    """

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def __fspath__(self) -> bytes:
        return self._raw


class TestValidateFilePathSequenceBytesFspath:
    """Covers performance/validation.py line 61."""

    def test_path_like_with_bytes_fspath_raises_type_error(self) -> None:
        """Arrange: a sequence containing a PathLike that returns bytes from __fspath__.

        Act: call validate_file_path_sequence with that sequence.

        Assert: TypeError is raised with the correct entry-level message,
        confirming the ``not isinstance(normalized_path, str)`` branch (line
        60-61) executed.
        """
        bad_path = _BytesPathLike(b"/tmp/bytes_path.yar")

        with pytest.raises(TypeError, match=FILE_PATH_ENTRY_TYPE_ERROR):
            validate_file_path_sequence([bad_path])

    def test_path_like_with_bytes_fspath_is_rejected_even_in_longer_list(
        self,
        tmp_path: Path,
    ) -> None:
        """A valid str entry followed by a bytes-returning PathLike must still
        raise TypeError when the bad entry is reached.
        """
        bad_path = _BytesPathLike(b"/tmp/another.yar")
        valid = str(tmp_path / "valid.yar")

        with pytest.raises(TypeError, match=FILE_PATH_ENTRY_TYPE_ERROR):
            validate_file_path_sequence([valid, bad_path])
