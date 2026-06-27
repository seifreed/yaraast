"""Targeted regression tests for yaraast.resolution.workspace missing coverage.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Missing lines addressed (as of baseline 93.14%):
  45-46  _path_is_dir OSError branch       -- unreachable without TOCTOU race; reported below
  75     _require_root_path None → cwd     -- covered by test_workspace_none_root_path_uses_cwd
  81-82  _require_root_path bytes-PathLike  -- covered by test_workspace_bytes_pathlike_root_path
  178-179 _require_workspace_path bytes-PL  -- covered by test_workspace_add_file_bytes_pathlike_path
              and test_workspace_add_dir_bytes_pathlike_path
  238    find_rule returns None             -- covered by test_workspace_find_rule_returns_none
  246    _iter_resolved_files dedup guard   -- covered by test_workspace_iter_resolved_files_dedup
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from yaraast.resolution.workspace import Workspace, _require_path_within_root

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> Path:
    path.write_text(content.strip() + "\n", encoding="utf-8")
    return path


class _BytesPathLike(os.PathLike[bytes]):
    """A PathLike whose __fspath__ returns bytes, not str.

    This is valid under the os.PathLike protocol (the protocol is generic),
    but the Workspace code expects a text path and must reject it cleanly.
    The guard ``isinstance(root_path, bool | bytes)`` does not catch this
    object because the object itself is not bytes — only its return value is.
    The OSError guard before the isinstance check on str | PathLike passes it
    through to ``os.fspath()``, which calls ``__fspath__()`` and returns bytes.
    That triggers the ``not isinstance(raw_path, str)`` branch.
    """

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def __fspath__(self) -> bytes:
        return self._raw


# ---------------------------------------------------------------------------
# Line 75: _require_root_path None → Path.cwd()
# ---------------------------------------------------------------------------


def test_workspace_none_root_path_uses_cwd() -> None:
    """Workspace(None) must set root_path to the current working directory.

    Line 75: ``return Path.cwd()``
    The ``if root_path is None`` guard returns cwd immediately, so no
    further validation is applied.
    """
    workspace = Workspace(root_path=None)

    assert workspace.root_path == Path.cwd()
    assert workspace.root_path.is_dir()


# ---------------------------------------------------------------------------
# Lines 81-82: _require_root_path with a PathLike whose fspath returns bytes
# ---------------------------------------------------------------------------


def test_workspace_bytes_pathlike_root_path_raises_type_error() -> None:
    """A PathLike returning bytes from __fspath__ must be rejected with TypeError.

    Lines 81-82: ``msg = "root_path must be a text path"; raise TypeError(msg)``
    The object passes the ``isinstance(root_path, str | PathLike)`` check, but
    ``os.fspath()`` returns bytes, which fails the ``isinstance(raw_path, str)``
    guard immediately after.
    """
    fake: Any = _BytesPathLike(b"/tmp/nonexistent")

    with pytest.raises(TypeError, match="root_path must be a text path"):
        Workspace(root_path=fake)


def test_workspace_null_byte_root_path_raises_value_error() -> None:
    with pytest.raises(ValueError, match="root_path must not contain null bytes"):
        Workspace(root_path="\x00broken")


def test_workspace_path_within_root_rejects_null_byte_path() -> None:
    with pytest.raises(ValueError, match="ctx must not contain null bytes"):
        _require_path_within_root(Path("\x00broken"), Path("/tmp"), name="ctx")


# ---------------------------------------------------------------------------
# Lines 178-179: _require_workspace_path with a PathLike returning bytes
#   (reached via add_file and add_directory)
# ---------------------------------------------------------------------------


def test_workspace_add_file_bytes_pathlike_path_raises_type_error(
    tmp_path: Path,
) -> None:
    """add_file with a PathLike returning bytes from __fspath__ must raise TypeError.

    Lines 178-179: the ``_require_workspace_path`` helper mirrors the
    ``_require_root_path`` non-str guard for workspace path arguments.
    """
    workspace = Workspace(str(tmp_path))
    fake: Any = _BytesPathLike(b"/tmp/rule.yar")

    with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
        workspace.add_file(fake)


def test_workspace_add_directory_bytes_pathlike_path_raises_type_error(
    tmp_path: Path,
) -> None:
    """add_directory with a PathLike returning bytes from __fspath__ must raise TypeError.

    Lines 178-179 are also reached through ``add_directory``, which calls
    ``_require_workspace_path`` with the ``directory`` argument.
    """
    workspace = Workspace(str(tmp_path))
    fake: Any = _BytesPathLike(b"/tmp/rules_dir")

    with pytest.raises(TypeError, match="directory must be a string or path-like object"):
        workspace.add_directory(fake)


# ---------------------------------------------------------------------------
# Line 238: find_rule returns None when no rule matches
# ---------------------------------------------------------------------------


def test_workspace_find_rule_returns_none_when_absent(tmp_path: Path) -> None:
    """find_rule must return None when the requested rule name is not in any file.

    Line 238: ``return None``
    The loop in ``find_rule`` exhausts all resolved files without finding a
    match, so the function falls through to the bare ``return None``.
    """
    yara_file = _write(
        tmp_path / "rules.yar",
        """
rule ExistingRule {
    strings:
        $a = "hello"
    condition:
        $a
}
""",
    )
    workspace = Workspace(str(tmp_path))
    workspace.add_file(str(yara_file))

    result = workspace.find_rule("NonExistentRule")

    assert result is None


def test_workspace_find_rule_returns_none_on_empty_workspace(tmp_path: Path) -> None:
    """find_rule on an empty workspace must return None.

    The file iteration produces nothing, so find_rule falls to line 238
    without entering any inner loop.
    """
    workspace = Workspace(str(tmp_path))

    result = workspace.find_rule("AnyRule")

    assert result is None


# ---------------------------------------------------------------------------
# Line 246: _iter_resolved_files deduplication guard
# ---------------------------------------------------------------------------


def test_workspace_iter_resolved_files_deduplication(tmp_path: Path) -> None:
    """A file included by two workspace files must appear exactly once in iteration.

    Line 246: ``if resolved.path in seen: return``
    When two workspace files both include a third shared file, the shared
    file's resolved tree is encountered twice during iteration.  The ``seen``
    set in ``walk`` short-circuits the second visit at line 246.

    Validation: get_all_rules() calls _iter_resolved_files() and must return
    each rule exactly once, even when included by multiple entry points.
    """
    shared = _write(
        tmp_path / "shared.yar",
        """
rule SharedRule {
    strings:
        $x = "shared"
    condition:
        $x
}
""",
    )
    entry_a = _write(
        tmp_path / "entry_a.yar",
        f"""
include "{shared}"

rule EntryARule {{
    strings:
        $a = "alpha"
    condition:
        $a
}}
""",
    )
    entry_b = _write(
        tmp_path / "entry_b.yar",
        f"""
include "{shared}"

rule EntryBRule {{
    strings:
        $b = "beta"
    condition:
        $b
}}
""",
    )

    workspace = Workspace(str(tmp_path))
    workspace.add_file(str(entry_a))
    workspace.add_file(str(entry_b))

    all_rules = workspace.get_all_rules()
    rule_names = [name for name, _ in all_rules]

    # SharedRule must appear exactly once despite being included by both entries.
    assert rule_names.count("SharedRule") == 1
    # Each entry's own rule must appear exactly once.
    assert rule_names.count("EntryARule") == 1
    assert rule_names.count("EntryBRule") == 1


def test_workspace_find_rule_finds_shared_rule_once(tmp_path: Path) -> None:
    """find_rule must return a result and not revisit the shared include.

    Line 246 is exercised when the shared file is encountered a second time
    during the find_rule traversal; the guard must short-circuit correctly
    and find_rule must still return the matching rule from the shared file.
    """
    shared = _write(
        tmp_path / "shared.yar",
        """
rule TargetRule {
    strings:
        $t = "target"
    condition:
        $t
}
""",
    )
    entry_a = _write(
        tmp_path / "a.yar",
        f"""
include "{shared}"
""",
    )
    entry_b = _write(
        tmp_path / "b.yar",
        f"""
include "{shared}"
""",
    )

    workspace = Workspace(str(tmp_path))
    workspace.add_file(str(entry_a))
    workspace.add_file(str(entry_b))

    found = workspace.find_rule("TargetRule")

    assert found is not None
    file_path, rule = found
    assert rule.name == "TargetRule"
    assert "shared.yar" in file_path


# ---------------------------------------------------------------------------
# Note on line 45-46 (_path_is_dir OSError branch)
# ---------------------------------------------------------------------------
# Lines 45-46 are NOT covered by this suite because they require a TOCTOU
# race condition: path.exists() must return True but path.is_dir() must then
# immediately raise OSError before returning.  This can only occur at the OS
# level if the filesystem atomically changes state between the two syscalls.
# Triggering it without mocking the Path object is not deterministically
# possible.  The branch is retained as a defensive guard in the source.
