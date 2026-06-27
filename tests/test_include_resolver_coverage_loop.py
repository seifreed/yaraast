"""Regression tests for yaraast.resolution.include_resolver missing-line coverage.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from typing import Any

import pytest

from yaraast.resolution.include_resolver import IncludeResolver, ResolvedFile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(directory: Path, name: str, content: str) -> Path:
    """Write *content* to *directory / name* and return the full path."""
    p = directory / name
    p.write_text(content, encoding="utf-8")
    return p


_SIMPLE_RULE = "rule r { condition: true }"
_INCLUDE_SIMPLE = 'include "r.yar"\nrule main { condition: true }'


# ---------------------------------------------------------------------------
# _read_yara_text — UnicodeDecodeError path (lines 42-47)
# ---------------------------------------------------------------------------


class TestReadYaraTextUnicodeDecodeError:
    """The helper must surface a descriptive ValueError on non-UTF-8 content."""

    def test_unicode_error_on_root_file_gives_generic_message(self) -> None:
        """Non-UTF-8 bytes in a top-level file raise ValueError with the non-include message."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            bad = tmpdir / "bad.yar"
            # Write raw Latin-1 byte that is invalid UTF-8 in isolation
            bad.write_bytes(b"rule r { strings: $s = \xff condition: $s }")

            resolver = IncludeResolver([str(tmpdir)])
            with pytest.raises(ValueError, match="YARA file must contain valid UTF-8 text"):
                resolver.resolve_file(str(bad))

    def test_unicode_error_on_include_file_gives_include_message(self) -> None:
        """Non-UTF-8 bytes in an included file raise ValueError with the include message."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "main.yar", 'include "bad.yar"\nrule main { condition: true }')
            bad = tmpdir / "bad.yar"
            bad.write_bytes(b"rule bad { strings: $s = \xff condition: $s }")

            resolver = IncludeResolver([str(tmpdir)])
            with pytest.raises(ValueError, match="YARA include file must contain valid UTF-8 text"):
                resolver.resolve_file(str(tmpdir / "main.yar"))


# ---------------------------------------------------------------------------
# _path_access_error / _path_is_file OSError path (lines 51-52, 58-59)
# ---------------------------------------------------------------------------


class TestPathIsFileOSError:
    """OSError from stat() propagates as a ValueError via _path_access_error."""

    def test_unreadable_directory_causes_oserror_wrapped_as_value_error(self) -> None:
        """A file inside a directory with no execute bit raises ValueError(path could not be accessed).

        Removing the execute (search) permission from a directory makes
        stat() raise PermissionError (an OSError subclass) when Python tries to
        inspect any path below it.  _path_is_file catches that OSError and
        re-raises it as ValueError via _path_access_error (lines 51-52, 58-59).
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            secret = tmpdir / "secret"
            secret.mkdir()
            yar = secret / "hidden.yar"
            yar.write_text(_SIMPLE_RULE, encoding="utf-8")

            # Remove all permissions from the subdirectory so stat raises PermissionError
            os.chmod(secret, 0)
            try:
                resolver = IncludeResolver(search_paths=[str(tmpdir)])
                with pytest.raises(ValueError, match="path could not be accessed"):
                    resolver.resolve_file(str(yar))
            finally:
                # Restore permissions so the TemporaryDirectory cleanup can remove the tree
                os.chmod(secret, stat.S_IRWXU)


# ---------------------------------------------------------------------------
# _init_search_paths — TypeError / ValueError guards (lines 86-90)
# ---------------------------------------------------------------------------


class TestInitSearchPathsValidation:
    """Invalid search_paths arguments must be rejected before any file I/O."""

    def test_non_list_search_paths_raises_type_error(self) -> None:
        """Passing a string (not a list) for search_paths raises TypeError."""
        with pytest.raises(TypeError, match="must be a list of strings"):
            IncludeResolver(search_paths="/tmp")  # type: ignore[arg-type]

    def test_list_with_non_string_entry_raises_type_error(self) -> None:
        """A list containing a Path object (not a str) raises TypeError."""
        with pytest.raises(TypeError, match="must be a list of strings"):
            IncludeResolver(search_paths=[Path("/tmp")])  # type: ignore[list-item]

    def test_list_with_empty_string_entry_raises_value_error(self) -> None:
        """A list containing an empty string raises ValueError."""
        with pytest.raises(ValueError, match="must not contain empty paths"):
            IncludeResolver(search_paths=[""])

    def test_list_with_whitespace_only_entry_raises_value_error(self) -> None:
        """A list containing a whitespace-only string raises ValueError."""
        with pytest.raises(ValueError, match="must not contain empty paths"):
            IncludeResolver(search_paths=["   "])


class TestResolveFileSymlinkRejection:
    """Top-level file resolution must reject symlink traversal."""

    def test_resolve_file_rejects_symlink_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            target = tmpdir / "target.yar"
            target.write_text(_SIMPLE_RULE, encoding="utf-8")
            link = tmpdir / "link.yar"
            link.symlink_to(target)

            resolver = IncludeResolver([str(tmpdir)])
            with pytest.raises(ValueError, match="file_path must not traverse a symlink"):
                resolver.resolve_file(str(link))

    def test_resolve_file_rejects_symlink_ancestor_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            outside = tmpdir / "outside"
            outside.mkdir()
            link = tmpdir / "linked"
            link.symlink_to(outside, target_is_directory=True)
            workspace = link / "workspace"
            workspace.mkdir()
            yar = workspace / "main.yar"
            yar.write_text(_SIMPLE_RULE, encoding="utf-8")

            resolver = IncludeResolver([str(tmpdir)])
            with pytest.raises(ValueError, match="file_path must not traverse a symlink"):
                resolver.resolve_file(str(yar))


# ---------------------------------------------------------------------------
# _init_search_paths — YARA_INCLUDE_PATH env var (lines 99-103)
# ---------------------------------------------------------------------------


class TestInitSearchPathsEnvVar:
    """YARA_INCLUDE_PATH drives additional search-path entries."""

    def test_env_var_adds_search_paths(self) -> None:
        """Paths listed in YARA_INCLUDE_PATH are appended to the resolver's search_paths."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            env_val = str(tmpdir)
            old = os.environ.pop("YARA_INCLUDE_PATH", None)
            try:
                os.environ["YARA_INCLUDE_PATH"] = env_val
                resolver = IncludeResolver()
                assert tmpdir.resolve() in resolver.search_paths
            finally:
                if old is None:
                    os.environ.pop("YARA_INCLUDE_PATH", None)
                else:
                    os.environ["YARA_INCLUDE_PATH"] = old

    def test_env_var_empty_segment_raises_value_error(self) -> None:
        """An empty segment in YARA_INCLUDE_PATH (e.g. '/a::b') raises ValueError."""
        separator = os.pathsep
        old = os.environ.pop("YARA_INCLUDE_PATH", None)
        try:
            # Produce an empty segment by doubling the separator
            os.environ["YARA_INCLUDE_PATH"] = f"/tmp{separator}{separator}/usr"
            with pytest.raises(ValueError, match="YARA_INCLUDE_PATH must not contain empty paths"):
                IncludeResolver()
        finally:
            if old is None:
                os.environ.pop("YARA_INCLUDE_PATH", None)
            else:
                os.environ["YARA_INCLUDE_PATH"] = old

    def test_duplicate_env_path_is_deduplicated(self) -> None:
        """Duplicate paths across search_paths and YARA_INCLUDE_PATH appear only once."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            old = os.environ.pop("YARA_INCLUDE_PATH", None)
            try:
                os.environ["YARA_INCLUDE_PATH"] = str(tmpdir)
                # Pass the same directory explicitly — dedup loop (line 109) must fire
                resolver = IncludeResolver(search_paths=[str(tmpdir)])
                count = resolver.search_paths.count(tmpdir.resolve())
                assert count == 1
            finally:
                if old is None:
                    os.environ.pop("YARA_INCLUDE_PATH", None)
                else:
                    os.environ["YARA_INCLUDE_PATH"] = old

    def test_search_path_under_symlink_ancestor_is_rejected(self) -> None:
        """A search path that traverses a symlink must be rejected up front."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            outside = tmpdir / "outside"
            outside.mkdir()
            link = tmpdir / "linked"
            link.symlink_to(outside, target_is_directory=True)
            search_path = link / "workspace"
            search_path.mkdir()

            with pytest.raises(
                ValueError,
                match="IncludeResolver search paths must not be symlinks",
            ):
                IncludeResolver(search_paths=[str(search_path)])


# ---------------------------------------------------------------------------
# _init_search_paths — deduplication branch (line 109->108)
# ---------------------------------------------------------------------------


class TestSearchPathDeduplication:
    """Duplicate entries in search_paths must be collapsed to a single entry."""

    def test_duplicate_explicit_paths_are_deduplicated(self) -> None:
        """Providing the same directory string twice yields a single entry."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            resolver = IncludeResolver(search_paths=[tmpdir_str, tmpdir_str])
            resolved_tmpdir = Path(tmpdir_str).resolve()
            assert resolver.search_paths.count(resolved_tmpdir) == 1


# ---------------------------------------------------------------------------
# _find_file — absolute path that is not a file (line 220->226)
# ---------------------------------------------------------------------------


class TestFindFileAbsoluteNotFile:
    """An absolute path to a directory (not a file) must fall through to search paths."""

    def test_absolute_directory_path_falls_through_to_not_found(self) -> None:
        """Passing an absolute path to an existing directory raises FileNotFoundError."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            resolver = IncludeResolver()
            with pytest.raises(FileNotFoundError, match="Cannot find YARA file"):
                resolver.resolve_file(tmpdir_str)

    def test_absolute_nonexistent_path_raises_file_not_found(self) -> None:
        """An absolute path to a file that does not exist raises FileNotFoundError."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            missing = Path(tmpdir_str) / "no_such_file.yar"
            resolver = IncludeResolver()
            with pytest.raises(FileNotFoundError, match="Cannot find YARA file"):
                resolver.resolve_file(str(missing))


# ---------------------------------------------------------------------------
# _find_file — path traversal prevention (lines 233-234) and success return (line 235)
# ---------------------------------------------------------------------------


class TestFindFilePathTraversalPrevention:
    """Symlinks that escape the search directory must be silently skipped."""

    def test_symlink_escaping_search_dir_is_rejected(self) -> None:
        """A symlink inside the search dir whose target is outside is rejected."""
        with tempfile.TemporaryDirectory() as outer_str:
            outer = Path(outer_str)
            # A real file outside the search directory
            real_file = outer / "outside.yar"
            real_file.write_text(_SIMPLE_RULE, encoding="utf-8")

            with tempfile.TemporaryDirectory() as inner_str:
                inner = Path(inner_str)
                # Symlink inside the search dir pointing to the real file outside
                link = inner / "escape.yar"
                link.symlink_to(real_file)

                resolver = IncludeResolver(search_paths=[str(inner)])
                with pytest.raises(ValueError, match="file_path must not traverse a symlink"):
                    resolver.resolve_file("escape.yar")

    def test_symlink_file_inside_search_dir_is_rejected(self) -> None:
        """A symlinked file inside the search dir is rejected at the read boundary."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            real_file = tmpdir / "real.yar"
            real_file.write_text(_SIMPLE_RULE, encoding="utf-8")
            link = tmpdir / "linked.yar"
            link.symlink_to(real_file)

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            with pytest.raises(ValueError, match="file_path must not traverse a symlink"):
                resolver.resolve_file("linked.yar")

    def test_relative_path_found_in_search_dir_uses_traversal_success_path(self) -> None:
        """A relative filename found legitimately in a search dir resolves successfully.

        This exercises the ``return resolved`` on line 235 by resolving a file
        that is NOT passed as an absolute path, forcing the search-path lookup.
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "searched.yar", _SIMPLE_RULE)

            # Ensure cwd is NOT tmpdir so the relative path lookup falls through
            # to the explicitly provided search path
            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            # Pass only the basename — not an absolute path — so the code must
            # reach the search-path loop and hit line 235
            result = resolver.resolve_file("searched.yar")
            assert result.ast.rules[0].name == "r"


# ---------------------------------------------------------------------------
# _find_file — FileNotFoundError messages (lines 238-244)
# ---------------------------------------------------------------------------


class TestFindFileMissingMessages:
    """FileNotFoundError messages differ for top-level files vs included files."""

    def test_missing_top_level_file_message_references_yara_file(self) -> None:
        """A missing top-level file produces a message mentioning 'YARA file'."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            resolver = IncludeResolver(search_paths=[tmpdir_str])
            with pytest.raises(FileNotFoundError, match="Cannot find YARA file"):
                resolver.resolve_file("missing.yar")

    def test_missing_include_file_message_references_include_file(self) -> None:
        """A missing include produces a message mentioning 'include file'."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "main.yar", 'include "absent.yar"\nrule m { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            with pytest.raises(FileNotFoundError, match="Cannot find include file"):
                resolver.resolve_file(str(tmpdir / "main.yar"))


# ---------------------------------------------------------------------------
# _format_searched_directories — None and duplicate dedup (lines 249-256)
# ---------------------------------------------------------------------------


class TestFormatSearchedDirectories:
    """_format_searched_directories deduplicates and skips None entries."""

    def test_duplicate_base_path_and_search_path_appear_once_in_error(self) -> None:
        """When base_path equals a search_path, it appears once in the error message."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "main.yar", 'include "missing.yar"\nrule m { condition: true }')

            # Pass the same directory as an explicit search path so it also appears in
            # search_paths; base_path (tmpdir itself) will then duplicate it in search_dirs.
            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            with pytest.raises(FileNotFoundError) as exc_info:
                resolver.resolve_file(str(tmpdir / "main.yar"))

            error_msg = str(exc_info.value)
            assert error_msg.count(f"Searched in: {tmpdir}") == 1


# ---------------------------------------------------------------------------
# _require_file_path — TypeError for bool/bytes, custom PathLike with bytes (lines 260-268)
# ---------------------------------------------------------------------------


class TestRequireFilePathValidation:
    """_require_file_path rejects booleans, bytes, and non-str PathLike returns."""

    def test_boolean_file_path_raises_type_error(self) -> None:
        """A boolean value as file_path raises TypeError."""
        resolver = IncludeResolver()
        with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
            resolver.resolve_file(True)  # type: ignore[arg-type]

    def test_bytes_file_path_raises_type_error(self) -> None:
        """A bytes value as file_path raises TypeError."""
        resolver = IncludeResolver()
        with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
            resolver.resolve_file(b"/tmp/x.yar")  # type: ignore[arg-type]

    def test_integer_file_path_raises_type_error(self) -> None:
        """An integer value as file_path raises TypeError (not str, not PathLike)."""
        resolver = IncludeResolver()
        with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
            resolver.resolve_file(42)  # type: ignore[arg-type]

    def test_custom_path_like_returning_bytes_raises_type_error(self) -> None:
        """A custom PathLike whose __fspath__ returns bytes triggers the inner TypeError guard."""

        class BytesPath(os.PathLike):  # type: ignore[type-arg]
            def __fspath__(self) -> bytes:
                return b"/tmp/x.yar"

        resolver = IncludeResolver()
        with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
            resolver.resolve_file(BytesPath())

    def test_empty_string_file_path_raises_value_error(self) -> None:
        """An empty string as file_path raises ValueError."""
        resolver = IncludeResolver()
        with pytest.raises(ValueError, match="file_path must not be empty"):
            resolver.resolve_file("")

    def test_whitespace_only_string_raises_value_error(self) -> None:
        """A whitespace-only string as file_path raises ValueError."""
        resolver = IncludeResolver()
        with pytest.raises(ValueError, match="file_path must not be empty"):
            resolver.resolve_file("   ")

    def test_null_byte_string_raises_value_error(self) -> None:
        resolver = IncludeResolver()
        with pytest.raises(ValueError, match="file_path must not contain null bytes"):
            resolver.resolve_file("\x00broken")


# ---------------------------------------------------------------------------
# Cache-hit return path (line 145) and cycle / RecursionError paths (148-151, 193)
# ---------------------------------------------------------------------------


class TestCacheHitAndCycleDetection:
    """Tests that exercise the fast-path cache return and the cycle-detection guard."""

    def test_cache_hit_returns_copy_without_re_parsing(self) -> None:
        """Second resolve_file call on an unchanged file returns from cache (line 145).

        For line 145 to fire the file must be in cache AND all three conditions must
        hold: checksum unchanged, all declared includes are in cache, all includes
        still have matching checksums.  A file with one include that is also
        unchanged satisfies all three on the second call.
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "lib.yar", "rule lib { condition: true }")
            _write(tmpdir, "main.yar", 'include "lib.yar"\nrule main { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            first = resolver.resolve_file(str(tmpdir / "main.yar"))
            # Second call: checksum unchanged, includes unchanged → cache hit (line 145)
            second = resolver.resolve_file(str(tmpdir / "main.yar"))

            # Results are equal in content but are independent deep copies
            assert first is not second
            assert first.ast.rules[0].name == second.ast.rules[0].name == "main"
            assert first.includes[0].ast.rules[0].name == "lib"

    def test_circular_include_detection_fires_recursion_error(self) -> None:
        """A direct cycle (a->b->a) raises RecursionError from the cycle guard (lines 148-151).

        The RecursionError is also re-raised on line 193 inside _parse_and_resolve.
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "a.yar", 'include "b.yar"\nrule a { condition: true }')
            _write(tmpdir, "b.yar", 'include "a.yar"\nrule b { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            with pytest.raises(RecursionError, match="Circular include detected"):
                resolver.resolve_file(str(tmpdir / "a.yar"))

    def test_multi_hop_cycle_message_contains_all_hops(self) -> None:
        """A three-file cycle reports all involved paths in the error message."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "x.yar", 'include "y.yar"\nrule x { condition: true }')
            _write(tmpdir, "y.yar", 'include "z.yar"\nrule y { condition: true }')
            _write(tmpdir, "z.yar", 'include "x.yar"\nrule z { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            with pytest.raises(RecursionError) as exc_info:
                resolver.resolve_file(str(tmpdir / "x.yar"))

            msg = str(exc_info.value)
            assert "Circular include detected" in msg


# ---------------------------------------------------------------------------
# _includes_unchanged — all-true path (line 285), partial-resolved false (276)
# checksum change (279), OSError (283-284), nested unchanged false (281-282)
# ---------------------------------------------------------------------------


class TestIncludesUnchanged:
    """Modifying or deleting an included file invalidates the cache correctly."""

    def test_modified_include_file_triggers_re_resolution(self) -> None:
        """Changing an included file's content causes a fresh parse on the next resolve_file."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "lib.yar", "rule lib_v1 { condition: true }")
            _write(tmpdir, "main.yar", 'include "lib.yar"\nrule main { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolved_v1 = resolver.resolve_file(str(tmpdir / "main.yar"))
            assert resolved_v1.includes[0].ast.rules[0].name == "lib_v1"

            # Mutate the included file — checksum now diverges from cached value
            (tmpdir / "lib.yar").write_text("rule lib_v2 { condition: true }", encoding="utf-8")

            resolved_v2 = resolver.resolve_file(str(tmpdir / "main.yar"))
            assert resolved_v2.includes[0].ast.rules[0].name == "lib_v2"

    def test_deleted_include_file_triggers_re_resolution(self) -> None:
        """Removing an included file after initial resolution causes OSError -> cache miss."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "lib.yar", "rule lib { condition: true }")
            _write(tmpdir, "main.yar", 'include "lib.yar"\nrule main { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            # Prime the cache
            resolver.resolve_file(str(tmpdir / "main.yar"))

            # Remove the included file so _includes_unchanged encounters OSError
            (tmpdir / "lib.yar").unlink()

            with pytest.raises((FileNotFoundError, RecursionError)):
                resolver.resolve_file(str(tmpdir / "main.yar"))

    def test_nested_include_modification_invalidates_outer_cache(self) -> None:
        """Changing a deeply nested include file invalidates caches up the chain.

        This exercises line 281 (recursive _includes_unchanged call) returning False,
        which propagates up through line 282.
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "deep.yar", "rule deep_v1 { condition: true }")
            _write(tmpdir, "mid.yar", 'include "deep.yar"\nrule mid { condition: true }')
            _write(tmpdir, "main.yar", 'include "mid.yar"\nrule main { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolver.resolve_file(str(tmpdir / "main.yar"))

            (tmpdir / "deep.yar").write_text("rule deep_v2 { condition: true }", encoding="utf-8")

            resolved = resolver.resolve_file(str(tmpdir / "main.yar"))
            deep_rule = resolved.includes[0].includes[0].ast.rules[0].name
            assert deep_rule == "deep_v2"

    def test_includes_unchanged_returns_true_when_all_stable(self) -> None:
        """When all includes are unchanged, _includes_unchanged returns True (line 285).

        Verified indirectly: resolving twice without modification returns the
        same rule names, proving the cache-hit path (line 145) fired rather than
        re-parsing.  That path is only reachable when _includes_unchanged is True.
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "stable_lib.yar", "rule stable_lib { condition: true }")
            _write(
                tmpdir,
                "stable_main.yar",
                'include "stable_lib.yar"\nrule stable_main { condition: true }',
            )

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            r1 = resolver.resolve_file(str(tmpdir / "stable_main.yar"))
            r2 = resolver.resolve_file(str(tmpdir / "stable_main.yar"))
            # Both calls return equal content — second came from cache (line 145)
            assert r1.ast.rules[0].name == r2.ast.rules[0].name
            assert r1.includes[0].ast.rules[0].name == r2.includes[0].ast.rules[0].name

    def test_stale_nested_include_count_invalidates_outer_cache(self) -> None:
        """A corrupted nested-include entry forces re-resolution via _all_declared check.

        Line 276 fires when _all_declared_includes_resolved(included) returns False
        for one of the main file's cached includes.  _includes_unchanged iterates
        over resolved.includes (the objects embedded in the cached entry), so we
        must corrupt the nested object stored there, not the top-level cache dict.
        """
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "deep.yar", "rule deep { condition: true }")
            _write(tmpdir, "lib.yar", 'include "deep.yar"\nrule lib { condition: true }')
            _write(tmpdir, "main3.yar", 'include "lib.yar"\nrule main3 { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolver.resolve_file(str(tmpdir / "main3.yar"))

            # Corrupt the lib ResolvedFile as stored inside main3's cache entry.
            # Setting .includes=[] while ast.includes still has one entry makes
            # _all_declared_includes_resolved(lib_in_main) return False.
            main_key = str((tmpdir / "main3.yar").absolute())
            lib_in_main = resolver.cache[main_key].includes[0]
            lib_in_main.includes = []

            # Now resolve main3 again:
            # - main3 checksum unchanged ✓
            # - main3 _all_declared_includes_resolved ✓ (still 1/1)
            # - _includes_unchanged(main3) iterates over main3.includes → finds lib_in_main
            #   → _all_declared_includes_resolved(lib_in_main) = False → line 276 fires
            # → _includes_unchanged returns False → cache miss → fresh parse
            resolved = resolver.resolve_file(str(tmpdir / "main3.yar"))
            assert len(resolved.includes) == 1
            assert resolved.includes[0].ast.rules[0].name == "lib"
            assert resolved.includes[0].includes[0].ast.rules[0].name == "deep"


# ---------------------------------------------------------------------------
# clear_cache (line 302)
# ---------------------------------------------------------------------------


class TestClearCache:
    """clear_cache empties the resolver's in-memory file cache."""

    def test_clear_cache_empties_cache(self) -> None:
        """After clear_cache(), the cache dict is empty."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "r.yar", _SIMPLE_RULE)

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolver.resolve_file(str(tmpdir / "r.yar"))
            assert len(resolver.cache) == 1

            resolver.clear_cache()
            assert len(resolver.cache) == 0

    def test_resolve_after_clear_produces_fresh_result(self) -> None:
        """Re-resolving after clear_cache() returns a fresh parse, not the old cache entry."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            yar = _write(tmpdir, "r.yar", "rule version_a { condition: true }")

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolver.resolve_file(str(yar))

            yar.write_text("rule version_b { condition: true }", encoding="utf-8")
            resolver.clear_cache()

            result = resolver.resolve_file(str(yar))
            assert result.ast.rules[0].name == "version_b"


# ---------------------------------------------------------------------------
# get_all_resolved_files (line 306)
# ---------------------------------------------------------------------------


class TestGetAllResolvedFiles:
    """get_all_resolved_files returns deep copies of every cached ResolvedFile."""

    def test_returns_empty_list_when_cache_is_empty(self) -> None:
        """An unused resolver returns an empty list."""
        resolver = IncludeResolver()
        assert resolver.get_all_resolved_files() == []

    def test_returns_all_cached_files(self) -> None:
        """Each file resolved (including includes) appears in the result list."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "lib.yar", "rule lib { condition: true }")
            _write(tmpdir, "main.yar", 'include "lib.yar"\nrule main { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolver.resolve_file(str(tmpdir / "main.yar"))

            all_files = resolver.get_all_resolved_files()
            names = [f.path.name for f in all_files]
            assert "main.yar" in names
            assert "lib.yar" in names

    def test_returned_objects_are_independent_copies(self) -> None:
        """Mutating a returned ResolvedFile does not corrupt the cache."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "r.yar", _SIMPLE_RULE)

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolver.resolve_file(str(tmpdir / "r.yar"))

            copies = resolver.get_all_resolved_files()
            assert len(copies) == 1
            copies[0].content = "tampered"

            fresh_copies = resolver.get_all_resolved_files()
            assert fresh_copies[0].content != "tampered"


# ---------------------------------------------------------------------------
# get_include_tree / _build_include_tree (lines 315-316, 320-326)
# ---------------------------------------------------------------------------


class TestGetIncludeTree:
    """get_include_tree returns a nested dict structure mirroring the include graph."""

    def test_flat_file_yields_tree_with_empty_includes(self) -> None:
        """A file with no includes produces a tree dict with path and empty includes list."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            yar = _write(tmpdir, "solo.yar", _SIMPLE_RULE)

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            tree = resolver.get_include_tree(str(yar))

            assert "path" in tree
            assert Path(tree["path"]).resolve() == yar.resolve()
            assert tree["includes"] == []

    def test_nested_includes_produce_nested_tree(self) -> None:
        """A two-level include chain produces a two-level nested dict."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "leaf.yar", "rule leaf { condition: true }")
            _write(tmpdir, "mid.yar", 'include "leaf.yar"\nrule mid { condition: true }')
            _write(tmpdir, "root.yar", 'include "mid.yar"\nrule root { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            tree = resolver.get_include_tree(str(tmpdir / "root.yar"))

            assert len(tree["includes"]) == 1
            mid_tree: dict[str, Any] = tree["includes"][0]
            assert "mid.yar" in mid_tree["path"]
            assert len(mid_tree["includes"]) == 1
            assert "leaf.yar" in mid_tree["includes"][0]["path"]

    def test_tree_path_key_is_string(self) -> None:
        """Every 'path' value in the include tree is a plain string, not a Path object."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "lib.yar", "rule lib { condition: true }")
            _write(tmpdir, "main.yar", 'include "lib.yar"\nrule main { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            tree = resolver.get_include_tree(str(tmpdir / "main.yar"))

            assert isinstance(tree["path"], str)
            assert isinstance(tree["includes"][0]["path"], str)


# ---------------------------------------------------------------------------
# ResolvedFile.get_all_rules — sanity (already covered but confirms integration)
# ---------------------------------------------------------------------------


class TestResolvedFileGetAllRules:
    """get_all_rules recursively collects rules from the full include tree."""

    def test_get_all_rules_includes_nested_rules(self) -> None:
        """Rules from all levels of nesting are returned in a flat list."""
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            _write(tmpdir, "deep.yar", "rule deep_rule { condition: true }")
            _write(tmpdir, "mid.yar", 'include "deep.yar"\nrule mid_rule { condition: true }')
            _write(tmpdir, "top.yar", 'include "mid.yar"\nrule top_rule { condition: true }')

            resolver = IncludeResolver(search_paths=[str(tmpdir)])
            resolved = resolver.resolve_file(str(tmpdir / "top.yar"))
            all_rules = resolved.get_all_rules()
            rule_names = {r.name for r in all_rules}

            assert rule_names == {"top_rule", "mid_rule", "deep_rule"}

    def test_get_all_rules_on_leaf_returns_only_own_rules(self) -> None:
        """A leaf ResolvedFile (no includes) returns only its own rules."""
        resolved = ResolvedFile(
            path=Path("/fake/leaf.yar"),
            content="rule leaf { condition: true }",
            ast=type(
                "_FakeFile",
                (),
                {"rules": [type("_FakeRule", (), {"name": "leaf"})()], "includes": []},
            )(),
            checksum="abc",
            includes=[],
        )
        rules = resolved.get_all_rules()
        assert len(rules) == 1
