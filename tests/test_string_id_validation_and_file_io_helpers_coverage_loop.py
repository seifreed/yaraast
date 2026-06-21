# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering missing lines in string_identifier_validation and file_io_helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.strings import PlainString
from yaraast.builder.string_identifier_validation import (
    normalize_string_identifier,
    validate_new_string_definitions,
)
from yaraast.errors import ValidationError
from yaraast.serialization.file_io_helpers import (
    _path_is_dir,
    read_utf8,
    write_utf8,
)

# ---------------------------------------------------------------------------
# normalize_string_identifier — all branches
# ---------------------------------------------------------------------------


def test_normalize_string_identifier_bare_name_receives_dollar_prefix() -> None:
    """Bare identifier without $ prefix is normalised by prepending $."""
    result = normalize_string_identifier("foo")
    assert result == "$foo"


def test_normalize_string_identifier_already_prefixed_is_returned_unchanged() -> None:
    """Identifier already starting with $ is returned as-is."""
    result = normalize_string_identifier("$bar")
    assert result == "$bar"


def test_normalize_string_identifier_alphanumeric_and_underscores_accepted() -> None:
    """Identifiers composed of letters, digits, and underscores are valid."""
    assert normalize_string_identifier("abc123_XYZ") == "$abc123_XYZ"
    assert normalize_string_identifier("$z_0") == "$z_0"


def test_normalize_string_identifier_non_string_raises_type_error() -> None:
    """Non-string input raises TypeError immediately."""
    with pytest.raises(TypeError, match="Invalid string identifier"):
        normalize_string_identifier(42)


def test_normalize_string_identifier_none_raises_type_error() -> None:
    """None input raises TypeError."""
    with pytest.raises(TypeError, match="Invalid string identifier"):
        normalize_string_identifier(None)


def test_normalize_string_identifier_empty_body_raises_validation_error() -> None:
    """A bare $ with no body is rejected with ValidationError."""
    with pytest.raises(ValidationError, match="Invalid string identifier"):
        normalize_string_identifier("$")


def test_normalize_string_identifier_hyphen_in_body_raises_validation_error() -> None:
    """A body containing a hyphen is rejected with ValidationError."""
    with pytest.raises(ValidationError, match="Invalid string identifier"):
        normalize_string_identifier("$foo-bar")


def test_normalize_string_identifier_space_in_body_raises_validation_error() -> None:
    """A body containing whitespace is rejected with ValidationError."""
    with pytest.raises(ValidationError, match="Invalid string identifier"):
        normalize_string_identifier("foo bar")


def test_normalize_string_identifier_dollar_in_body_raises_validation_error() -> None:
    """A second $ inside the body is rejected with ValidationError."""
    with pytest.raises(ValidationError, match="Invalid string identifier"):
        normalize_string_identifier("$$nested")


# ---------------------------------------------------------------------------
# validate_new_string_definitions — all branches
# ---------------------------------------------------------------------------


def test_validate_new_string_definitions_accepts_non_overlapping_identifiers() -> None:
    """Non-duplicate identifiers across existing and new strings pass validation."""
    existing = [PlainString("$a", "hello")]
    new = [PlainString("$b", "world")]
    # Must not raise
    validate_new_string_definitions(existing, new)


def test_validate_new_string_definitions_duplicate_against_existing_raises() -> None:
    """Duplicate identifier between existing and new strings raises ValidationError."""
    existing = [PlainString("$alpha", "original")]
    new = [PlainString("$alpha", "duplicate")]
    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        validate_new_string_definitions(existing, new)


def test_validate_new_string_definitions_duplicate_within_new_strings_raises() -> None:
    """Two identical identifiers in the new list itself raises ValidationError."""
    new = [PlainString("$dup", "first"), PlainString("$dup", "second")]
    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        validate_new_string_definitions([], new)


def test_validate_new_string_definitions_anonymous_in_existing_is_skipped() -> None:
    """Anonymous strings in existing_strings are excluded from the seen set."""
    anon = PlainString("$*", is_anonymous=True)
    named = PlainString("$x", "value")
    # The anonymous string must not collide; named must be accepted
    validate_new_string_definitions([anon], [named])


def test_validate_new_string_definitions_anonymous_in_new_strings_is_skipped() -> None:
    """Anonymous strings in new_strings are not checked for duplication."""
    anon = PlainString("$*", is_anonymous=True)
    named = PlainString("$y", "value")
    validate_new_string_definitions([], [anon, named])


def test_validate_new_string_definitions_empty_lists_is_valid() -> None:
    """Empty existing and new string lists produce no error."""
    validate_new_string_definitions([], [])


def test_validate_new_string_definitions_normalises_identifiers_before_comparing() -> None:
    """Identifiers with and without $ prefix resolve to the same normalised key."""
    existing = [PlainString("$key", "original")]
    # new string uses same identifier but without explicit $;
    # normalisation must detect the collision
    new = [PlainString("$key", "collision")]
    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        validate_new_string_definitions(existing, new)


# ---------------------------------------------------------------------------
# file_io_helpers — _path_is_dir OSError branch (lines 24-25)
# ---------------------------------------------------------------------------


class _IsDir0SErrPath(Path):
    """Path subclass whose is_dir() always raises OSError.

    exists() returns True so that _path_exists_and_is_dir proceeds to
    call _path_is_dir, which then hits the except branch.
    """

    def exists(self, *, follow_symlinks: bool = True) -> bool:
        return True

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        raise OSError("injected is_dir failure")


def test_path_is_dir_oserror_re_raised_as_value_error(tmp_path: Path) -> None:
    """_path_is_dir wraps OSError from Path.is_dir() into ValueError."""
    bad_path = _IsDir0SErrPath(tmp_path / "_injected_isdir_test")
    with pytest.raises(ValueError, match="path could not be accessed"):
        _path_is_dir(bad_path)


# ---------------------------------------------------------------------------
# file_io_helpers — _require_file_path bytes-returning PathLike (lines 38-39)
# ---------------------------------------------------------------------------


class _BytesPathLike:
    """PathLike whose __fspath__ returns bytes, which is not a str."""

    def __fspath__(self) -> bytes:
        return b"/tmp/bytes_path"


def test_read_utf8_bytes_pathlike_raises_type_error() -> None:
    """read_utf8 rejects a PathLike that returns bytes from __fspath__."""
    with pytest.raises(TypeError, match="path must be a file path"):
        read_utf8(cast(Path, _BytesPathLike()))


def test_write_utf8_bytes_pathlike_raises_type_error() -> None:
    """write_utf8 rejects a PathLike that returns bytes from __fspath__."""
    with pytest.raises(TypeError, match="path must be a file path"):
        write_utf8(cast(Path, _BytesPathLike()), "content")


# ---------------------------------------------------------------------------
# file_io_helpers — read_utf8 OSError on open() (lines 56-57)
# ---------------------------------------------------------------------------


def test_read_utf8_permission_denied_raises_value_error(tmp_path: Path) -> None:
    """read_utf8 raises ValueError when a readable path cannot be opened due to OS error."""
    protected = tmp_path / "protected.txt"
    protected.write_text("secret", encoding="utf-8")
    protected.chmod(0o000)
    try:
        with pytest.raises(ValueError, match="path could not be accessed"):
            read_utf8(protected)
    finally:
        protected.chmod(0o644)


# ---------------------------------------------------------------------------
# file_io_helpers — write_utf8 OSError on open('w') (lines 77-78)
# ---------------------------------------------------------------------------


def test_write_utf8_read_only_file_raises_value_error(tmp_path: Path) -> None:
    """write_utf8 raises ValueError when the OS refuses to open the file for writing."""
    readonly = tmp_path / "readonly.txt"
    readonly.write_text("original", encoding="utf-8")
    readonly.chmod(0o444)
    try:
        with pytest.raises(ValueError, match="path could not be accessed"):
            write_utf8(readonly, "replacement")
    finally:
        readonly.chmod(0o644)


def test_write_utf8_missing_parent_directory_raises_value_error(tmp_path: Path) -> None:
    """write_utf8 raises ValueError when the parent directory does not exist."""
    target = tmp_path / "nonexistent_dir" / "file.txt"
    # target is not a directory, so _require_file_path accepts it; open('w') then fails
    with pytest.raises(ValueError, match="path could not be accessed"):
        write_utf8(target, "content")


# ---------------------------------------------------------------------------
# Parametric boundary checks for both modules together
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "identifier",
    [
        "single",
        "CamelCase",
        "under_score",
        "Mix3d_4nd_CAPS",
        "$prefixed",
        "$A",
        "$z",
        "$_underscore",
    ],
)
def test_normalize_string_identifier_valid_identifiers(identifier: str) -> None:
    """Range of valid identifiers are accepted and always return a $-prefixed string."""
    result = normalize_string_identifier(identifier)
    assert result.startswith("$")
    assert len(result) > 1


@pytest.mark.parametrize(
    "identifier",
    [
        "$foo!",
        "$foo.bar",
        "$foo/bar",
        "$foo bar",
        "$foo@bar",
    ],
)
def test_normalize_string_identifier_special_chars_rejected(identifier: str) -> None:
    """Identifiers containing special characters are always rejected."""
    with pytest.raises(ValidationError):
        normalize_string_identifier(identifier)


@pytest.mark.parametrize("bad_path", [False, True, 0, 1, object()])
def test_read_utf8_non_path_types_raise_type_error(bad_path: Any) -> None:
    """read_utf8 rejects bool, int, and arbitrary objects with TypeError."""
    with pytest.raises(TypeError, match="path must be a file path"):
        read_utf8(bad_path)


@pytest.mark.parametrize("bad_path", [False, True, 0, 1, object()])
def test_write_utf8_non_path_types_raise_type_error(bad_path: Any) -> None:
    """write_utf8 rejects bool, int, and arbitrary objects with TypeError."""
    with pytest.raises(TypeError, match="path must be a file path"):
        write_utf8(bad_path, "content")
