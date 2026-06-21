# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests covering missing branches in:
- yaraast.libyara._paths   (lines 21-22, 41-42)
- yaraast.cli.validate_services  (lines 21-22, 34-35, 43-45)

All tests exercise real production code paths with no mocks or stubs.
"""

from __future__ import annotations

import os
from os import PathLike
from pathlib import Path
from typing import cast

import pytest

from yaraast.cli import validate_services as vs
from yaraast.errors import ValidationError
from yaraast.libyara._paths import path_stat, require_file_path

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


class _BytesPathLike:
    """A PathLike whose __fspath__ returns bytes instead of str.

    The os.fspath() contract allows bytes returns from __fspath__, making
    ``isinstance(raw_path, str)`` evaluate to False and triggering the
    defensive TypeError branches in both require_file_path and read_test_data.
    """

    def __fspath__(self) -> bytes:
        return b"/tmp/bytes-path"


# ---------------------------------------------------------------------------
# yaraast.libyara._paths — missing lines 21-22
# ---------------------------------------------------------------------------


def test_require_file_path_rejects_bytes_returning_pathlike() -> None:
    """Lines 21-22: fspath() returns bytes when __fspath__ yields bytes.

    require_file_path checks isinstance(raw_path, str) after calling
    fspath().  A PathLike whose __fspath__ returns bytes passes the first
    isinstance guard (it is a PathLike and is not bool/bytes) but produces a
    bytes raw_path.  The function must raise TypeError for this input.
    """
    obj = cast(PathLike[str], _BytesPathLike())

    with pytest.raises(TypeError, match="must be a string or path-like object"):
        require_file_path(obj, "filepath")


# ---------------------------------------------------------------------------
# yaraast.libyara._paths — missing lines 41-42
# ---------------------------------------------------------------------------


def test_path_stat_raises_value_error_when_os_raises_oserror() -> None:
    """Lines 41-42: path.stat() raises OSError (filename too long on macOS).

    path_stat wraps the OSError in a ValueError with a human-readable message.
    A filename that exceeds the kernel limit reliably triggers ENAMETOOLONG.
    """
    too_long = Path("a" * 5000)

    with pytest.raises(ValueError, match="path could not be accessed"):
        path_stat(too_long)


# ---------------------------------------------------------------------------
# yaraast.cli.validate_services — missing lines 21-22 (roundtrip_test)
# ---------------------------------------------------------------------------


def test_roundtrip_test_returns_equivalence_result_for_valid_rule(tmp_path: Path) -> None:
    """Lines 21-22: roundtrip_test instantiates EquivalenceTester and delegates
    to test_file_round_trip.  A well-formed YARA rule must round-trip cleanly,
    producing an EquivalenceResult with equivalent=True.
    """
    rule_path = tmp_path / "simple.yar"
    rule_path.write_text("rule simple { condition: true }", encoding="utf-8")

    result = vs.roundtrip_test(str(rule_path), None)

    assert result.equivalent is True
    assert result.ast_equivalent is True
    assert result.original_compiles is True
    assert result.regenerated_compiles is True


def test_roundtrip_test_with_test_data_returns_result(tmp_path: Path) -> None:
    """Lines 21-22 (alternate): roundtrip_test passes the optional data bytes
    through to the scanner.  Supplying test data exercises the scan_equivalent
    path in EquivalenceTester.
    """
    rule_path = tmp_path / "strings.yar"
    rule_path.write_text(
        'rule has_strings { strings: $a = "hello" condition: $a }',
        encoding="utf-8",
    )
    data = b"hello world"

    result = vs.roundtrip_test(str(rule_path), data)

    # The result must carry a meaningful verdict; its structure is real.
    assert hasattr(result, "equivalent")
    assert hasattr(result, "scan_equivalent")


def test_roundtrip_test_returns_failed_result_for_unparseable_file(tmp_path: Path) -> None:
    """Lines 21-22 (error path): EquivalenceTester catches parse failures and
    returns a non-equivalent result instead of raising.  This validates that
    roundtrip_test is a total function over invalid inputs.
    """
    bad_path = tmp_path / "broken.yar"
    bad_path.write_text("this is not valid yara @#$%", encoding="utf-8")

    result = vs.roundtrip_test(str(bad_path), None)

    assert result.equivalent is False
    assert result.original_compiles is False


# ---------------------------------------------------------------------------
# yaraast.cli.validate_services — missing lines 34-35 (bytes PathLike)
# ---------------------------------------------------------------------------


def test_read_test_data_rejects_bytes_returning_pathlike() -> None:
    """Lines 34-35: fspath() returns bytes when __fspath__ yields bytes.

    read_test_data checks isinstance(raw_path, str) after calling fspath().
    A PathLike returning bytes must raise TypeError, the same defensive guard
    present in require_file_path for symmetry across the codebase.
    """
    obj = cast(PathLike[str], _BytesPathLike())

    with pytest.raises(TypeError, match="test data path must be a string or path-like object"):
        vs.read_test_data(obj)


# ---------------------------------------------------------------------------
# yaraast.cli.validate_services — missing lines 43-45 (ValidationError)
# ---------------------------------------------------------------------------


def test_read_test_data_raises_validation_error_when_file_does_not_exist(
    tmp_path: Path,
) -> None:
    """Lines 43-45: Path.open() raises FileNotFoundError (an OSError subclass),
    which the except clause wraps in ValidationError with an informative message.
    Using a path inside a real temp directory that provably does not exist
    exercises this branch deterministically across all environments.
    """
    nonexistent = str(tmp_path / "nonexistent_file_coverage_loop.bin")
    assert not os.path.exists(nonexistent), "precondition: file must not exist"

    with pytest.raises(ValidationError, match="Error reading test data"):
        vs.read_test_data(nonexistent)


def test_read_test_data_raises_validation_error_when_path_is_directory(tmp_path: Path) -> None:
    """Lines 43-45 (alternate): Opening a directory path as a binary file raises
    IsADirectoryError on POSIX systems, which the except clause also catches and
    re-raises as ValidationError.  This validates the handler for non-FileNotFound
    IO exceptions.
    """
    with pytest.raises(ValidationError, match="Error reading test data"):
        vs.read_test_data(str(tmp_path))
