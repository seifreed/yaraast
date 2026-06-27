# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression coverage for yaraast/shared/file_patterns.py — missing branches.

Targets lines and branches not reached by the existing
tests/test_shared_file_patterns.py suite:
  - _path_is_dir  OSError branch                 (lines 31-32)
  - normalize_file_patterns: None  default return (line 41)
  - normalize_file_patterns: single str return    (line 45)
  - normalize_file_patterns: non-iterable TypeError (line 47)
  - normalize_file_patterns: iterable-of-str return (line 53)
  - iter_matching_files: PathLike[bytes] TypeError  (line 66)
  - iter_matching_files: glob loop, yield, dedup    (lines 83-88)
"""

from __future__ import annotations

import os
from os import PathLike
from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.shared.file_patterns import (
    DEFAULT_CLASSIC_YARA_FILE_PATTERNS,
    DIRECTORY_TYPE_ERROR,
    FILE_PATTERNS_TYPE_ERROR,
    iter_matching_files,
    normalize_file_patterns,
)


# ---------------------------------------------------------------------------
# Helper: a PathLike whose __fspath__ returns bytes, not str.
# os.fspath() will return the bytes value; the code then rejects it at
# line 65-66 because isinstance(raw_path, str) is False.
# ---------------------------------------------------------------------------
class _BytesPathLike:
    """PathLike implementation whose __fspath__ returns bytes, not str."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def __fspath__(self) -> bytes:
        return self._raw


# ---------------------------------------------------------------------------
# normalize_file_patterns — uncovered happy-path branches
# ---------------------------------------------------------------------------


class TestNormalizeFilePatternsDefaults:
    """normalize_file_patterns(None) must return the built-in default tuple."""

    def test_none_returns_classic_default(self) -> None:
        # Arrange: no patterns supplied
        # Act: call with the sentinel None value
        result = normalize_file_patterns(None)
        # Assert: the module-level constant is returned verbatim
        assert result == DEFAULT_CLASSIC_YARA_FILE_PATTERNS
        assert isinstance(result, tuple)

    def test_none_returns_custom_default_when_supplied(self) -> None:
        custom: tuple[str, ...] = ("*.rule",)
        result = normalize_file_patterns(None, default=custom)
        assert result == custom


class TestNormalizeFilePatternsStrInput:
    """normalize_file_patterns(str) must wrap the string in a 1-tuple."""

    def test_single_pattern_string_is_wrapped(self) -> None:
        result = normalize_file_patterns("*.yar")
        assert result == ("*.yar",)

    def test_pattern_with_leading_whitespace_is_preserved(self) -> None:
        # strip() is used only for the emptiness check; the value itself
        # is stored as-is.
        result = normalize_file_patterns(" *.yar ")
        assert result == (" *.yar ",)

    def test_single_extension_glob_roundtrips(self) -> None:
        result = normalize_file_patterns("*.yara")
        assert result == ("*.yara",)


class TestNormalizeFilePatternsNonIterable:
    """A non-iterable, non-str value must raise TypeError."""

    def test_integer_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match=FILE_PATTERNS_TYPE_ERROR):
            normalize_file_patterns(cast(Any, 42))

    def test_float_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match=FILE_PATTERNS_TYPE_ERROR):
            normalize_file_patterns(cast(Any, 3.14))


class TestNormalizeFilePatternsIterableOfStrings:
    """An iterable of valid strings must be returned as a tuple."""

    def test_list_of_patterns_becomes_tuple(self) -> None:
        result = normalize_file_patterns(["*.yar", "*.yara"])
        assert result == ("*.yar", "*.yara")
        assert isinstance(result, tuple)

    def test_generator_of_patterns_is_consumed(self) -> None:
        def gen() -> Any:
            yield "*.yar"
            yield "*.rule"

        result = normalize_file_patterns(gen())
        assert result == ("*.yar", "*.rule")

    def test_single_element_list_becomes_singleton_tuple(self) -> None:
        result = normalize_file_patterns(["*.bin"])
        assert result == ("*.bin",)

    def test_tuple_of_patterns_roundtrips(self) -> None:
        patterns = ("*.yar", "*.yara", "*.rule")
        result = normalize_file_patterns(patterns)
        assert result == patterns


# ---------------------------------------------------------------------------
# iter_matching_files — bytes PathLike rejected at fspath check (line 66)
# ---------------------------------------------------------------------------


class TestIterMatchingFilesBytesPathLike:
    """A PathLike whose __fspath__ returns bytes must be rejected."""

    def test_bytes_fspath_raises_type_error(self) -> None:
        # Arrange: build a PathLike[bytes]; bytes is not str, so line 65-66
        # must raise TypeError with the DIRECTORY_TYPE_ERROR message.
        bad: PathLike[bytes] = cast(PathLike[bytes], _BytesPathLike(b"/tmp"))
        # Act / Assert
        with pytest.raises(TypeError, match=DIRECTORY_TYPE_ERROR):
            list(iter_matching_files(cast(Any, bad)))


# ---------------------------------------------------------------------------
# iter_matching_files — real file-discovery (lines 83-88)
# ---------------------------------------------------------------------------


class TestIterMatchingFilesGlob:
    """iter_matching_files must yield real files that match the pattern."""

    def test_returns_empty_when_no_files_match(self, tmp_path: Path) -> None:
        # Arrange: directory exists but contains no .yar files
        (tmp_path / "readme.txt").write_text("not a yara file", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar"))
        # Assert
        assert result == []

    def test_yields_single_matching_file(self, tmp_path: Path) -> None:
        # Arrange
        yar_file = tmp_path / "rule.yar"
        yar_file.write_text("rule test { condition: true }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar"))
        # Assert: the exact real path is returned
        assert result == [yar_file]

    def test_yields_multiple_matching_files(self, tmp_path: Path) -> None:
        # Arrange: three .yar files
        files = [tmp_path / f"rule_{i}.yar" for i in range(3)]
        for f in files:
            f.write_text("rule dummy { condition: false }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar"))
        # Assert: all three are returned (order may vary by filesystem)
        assert sorted(result) == sorted(files)

    def test_skips_non_matching_files(self, tmp_path: Path) -> None:
        # Arrange: mix of .yar and .txt files
        yar = tmp_path / "rule.yar"
        yar.write_text("rule x { condition: true }", encoding="utf-8")
        (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar"))
        # Assert: only the .yar file is returned
        assert result == [yar]

    def test_uses_default_classic_yara_patterns_when_none(self, tmp_path: Path) -> None:
        # Arrange: one .yar and one .yara file
        yar = tmp_path / "a.yar"
        yara = tmp_path / "b.yara"
        yar.write_text("rule a { condition: true }", encoding="utf-8")
        yara.write_text("rule b { condition: true }", encoding="utf-8")
        # Act: patterns=None triggers the default ("*.yar", "*.yara")
        result = list(iter_matching_files(tmp_path))
        assert yar in result
        assert yara in result

    def test_string_directory_accepted(self, tmp_path: Path) -> None:
        # Arrange: pass directory as a plain str, not Path
        yar = tmp_path / "rule.yar"
        yar.write_text("rule x { condition: true }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(str(tmp_path), "*.yar"))
        # Assert: the real file is discovered
        assert len(result) == 1
        assert result[0].name == "rule.yar"

    def test_deduplicates_files_matched_by_multiple_patterns(self, tmp_path: Path) -> None:
        # Arrange: a single file with extension matching both patterns in list.
        # We use two overlapping glob patterns so the same file would be
        # yielded twice without the deduplication logic on line 85-87.
        yar = tmp_path / "malware.yar"
        yar.write_text("rule malware { condition: true }", encoding="utf-8")
        # "*.yar" and "malware.yar" both match the same file
        result = list(iter_matching_files(tmp_path, ["*.yar", "malware.yar"]))
        # Assert: file appears exactly once despite two patterns matching it
        assert result.count(yar) == 1
        assert len(result) == 1

    def test_non_recursive_does_not_descend_into_subdirectories(self, tmp_path: Path) -> None:
        # Arrange: a .yar file is nested inside a subdirectory
        subdir = tmp_path / "nested"
        subdir.mkdir()
        nested = subdir / "hidden.yar"
        nested.write_text("rule hidden { condition: true }", encoding="utf-8")
        top = tmp_path / "visible.yar"
        top.write_text("rule visible { condition: true }", encoding="utf-8")
        # Act: recursive=False (default)
        result = list(iter_matching_files(tmp_path, "*.yar", recursive=False))
        # Assert: only the top-level file is found
        assert result == [top]
        assert nested not in result

    def test_recursive_true_descends_into_subdirectories(self, tmp_path: Path) -> None:
        # Arrange
        subdir = tmp_path / "sub"
        subdir.mkdir()
        nested = subdir / "deep.yar"
        nested.write_text("rule deep { condition: true }", encoding="utf-8")
        top = tmp_path / "top.yar"
        top.write_text("rule top { condition: true }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar", recursive=True))
        # Assert: both files are discovered
        assert sorted(result) == sorted([top, nested])

    def test_recursive_deduplicates_across_multiple_patterns(self, tmp_path: Path) -> None:
        # Arrange: two patterns, both matching the same file recursively
        subdir = tmp_path / "sub"
        subdir.mkdir()
        target = subdir / "rule.yar"
        target.write_text("rule x { condition: true }", encoding="utf-8")
        # Act: two patterns that both match "rule.yar"
        result = list(iter_matching_files(tmp_path, ["*.yar", "rule.yar"], recursive=True))
        # Assert: yielded exactly once
        assert result.count(target) == 1

    def test_skips_directories_in_glob_results(self, tmp_path: Path) -> None:
        # Arrange: a subdirectory whose name matches the glob pattern
        # Path.glob("*.yar") can match a *directory* named "some.yar"
        # on some filesystems; the code filters non-files at line 85.
        fake_dir = tmp_path / "fake.yar"
        fake_dir.mkdir()
        real_file = tmp_path / "real.yar"
        real_file.write_text("rule real { condition: true }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar"))
        # Assert: the directory is excluded; only the real file is returned
        assert result == [real_file]
        assert fake_dir not in result

    def test_yields_path_objects_not_strings(self, tmp_path: Path) -> None:
        # Arrange
        yar = tmp_path / "check.yar"
        yar.write_text("rule check { condition: true }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar"))
        # Assert: every yielded item is a pathlib.Path
        assert all(isinstance(p, Path) for p in result)

    def test_path_object_directory_accepted(self, tmp_path: Path) -> None:
        # Arrange: pass a pathlib.Path directly
        yar = tmp_path / "path_obj.yar"
        yar.write_text("rule p { condition: true }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(tmp_path, "*.yar"))
        assert yar in result

    def test_os_fsencode_path_like_accepted(self, tmp_path: Path) -> None:
        # Arrange: a custom PathLike[str] object (not Path, not str) is accepted
        class StrPathLike(os.PathLike[str]):
            def __init__(self, path: Path) -> None:
                self._path = path

            def __fspath__(self) -> str:
                return str(self._path)

        yar = tmp_path / "custom.yar"
        yar.write_text("rule c { condition: true }", encoding="utf-8")
        # Act
        result = list(iter_matching_files(StrPathLike(tmp_path), "*.yar"))
        assert len(result) == 1
        assert result[0].name == "custom.yar"

    def test_rejects_symlinked_directory_root(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "outside.yar").write_text("rule outside { condition: true }", encoding="utf-8")
        link = tmp_path / "linked"
        link.symlink_to(outside, target_is_directory=True)

        with pytest.raises(ValueError, match="directory must not be a symlink"):
            list(iter_matching_files(link, "*.yar", recursive=True))

    def test_deduplicates_symlink_aliases_to_the_same_file(self, tmp_path: Path) -> None:
        real = tmp_path / "real.yar"
        real.write_text("rule real { condition: true }", encoding="utf-8")
        alias = tmp_path / "alias.yar"
        alias.symlink_to(real)

        result = list(iter_matching_files(tmp_path, "*.yar"))

        assert result == [real.resolve()]


# ---------------------------------------------------------------------------
# _path_is_dir OSError branch (lines 31-32)
# This branch is exercised by passing a path so long that is_dir() raises
# OSError before the path-exists check can succeed.
# The existing test suite already covers _path_exists via "a"*5000, but
# _path_is_dir's OSError branch requires a path that EXISTS (or appears to)
# yet raises on is_dir().  On macOS/Linux the same overlong path also makes
# path.exists() raise OSError first (line 22-25), so _path_is_dir's OSError
# line (31-32) is genuinely unreachable through the public API because
# _path_exists raises first.
# We verify that fact here with a direct call to the private helper.
# ---------------------------------------------------------------------------


class TestPathIsDirOSErrorBranch:
    """Document that _path_is_dir's OSError path is unreachable via the public API."""

    def test_path_access_error_raised_for_overlong_path_via_public_api(self) -> None:
        # An overlong path hits _path_exists first (line 22-25), which is
        # already covered by the existing suite.  We confirm the public API
        # still raises ValueError with the expected message.
        with pytest.raises(ValueError, match="path could not be accessed"):
            list(iter_matching_files("a" * 5000))

    def test_path_is_dir_oserror_branch_via_private_helper(self) -> None:
        # Import the private helper to exercise lines 31-32 directly.
        # This is the only way to reach that branch without OS-level trickery.
        from yaraast.shared.file_patterns import _path_is_dir

        with pytest.raises(ValueError, match="path could not be accessed"):
            _path_is_dir(Path("a" * 5000))
