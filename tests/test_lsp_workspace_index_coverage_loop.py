"""Coverage-gap tests for yaraast/lsp/workspace_index.py.

// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Each test targets one or more lines that remain uncovered after the existing
test_lsp_runtime_phase1.py suite runs.  No mocks are used — every assertion
exercises the real WorkspaceIndex implementation.

Missing lines addressed (module line numbers from coverage report):
  78            _cache_paths dedup — duplicate workspace folder collapsed
  85            _cache_path_for_root — file root resolved to parent
  91            _workspace_root_for_uri — non-routable URI returns None
 103->98        _workspace_root_for_path — shorter competing root not chosen
 111-112        _workspace_root_matches_path — OSError on root.resolve()
 114            _workspace_root_matches_path — file-root exact-path match
 135-137        load — corrupt JSON, logged and skipped
 142            load — payload root is not a dict, skipped
 145            load — raw_symbols entry has wrong types, skipped
 158            _load_symbol_records — non-dict symbol entry skipped
 186-187        save — OSError writing cache, logged and skipped
 221            search_records — excluded URI skipped
 231-232        iter_candidate_files — folder argument is a YARA file itself
 234            iter_candidate_files — folder exists but is neither file nor dir
 238-239        iter_candidate_files — OSError from rglob, logged and skipped
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.document_types import SymbolRecord
from yaraast.lsp.runtime import path_to_uri
from yaraast.lsp.workspace_index import WorkspaceIndex

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_symbol(name: str, uri: str) -> SymbolRecord:
    """Return a minimal valid SymbolRecord for the given name and URI."""
    return SymbolRecord(
        name=name,
        kind="rule",
        uri=uri,
        range=Range(
            start=Position(line=0, character=0),
            end=Position(line=0, character=len(name)),
        ),
    )


def _write_cache(cache_path: Path, payload: object) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Line 78 — _cache_paths deduplicates repeated workspace folders
# ---------------------------------------------------------------------------


def test_cache_paths_deduplicates_repeated_workspace_folder(tmp_path: Path) -> None:
    """When the same directory appears twice in workspace_folders, save writes
    to that cache file exactly once and loads without duplicating symbols."""
    yar = tmp_path / "alpha.yar"
    yar.write_text("rule alpha { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(yar)

    index = WorkspaceIndex()
    # Set the same root twice so _cache_paths must hit the dedup branch (line 78).
    index.workspace_folders = [tmp_path, tmp_path]

    record = _make_symbol("alpha", uri)
    index.persisted_symbols[uri] = [record]
    index.save()

    cache_path = tmp_path / ".yaraast" / "lsp-workspace-index.json"
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    # The cache must exist and contain the symbol exactly once.
    assert uri in payload["symbols"]
    assert len(payload["symbols"][uri]) == 1

    # Reload: symbols must appear exactly once despite the duplicated folder.
    restored = WorkspaceIndex()
    restored.workspace_folders = [tmp_path, tmp_path]
    restored.load()
    assert len(restored.persisted_symbols.get(uri, [])) == 1


# ---------------------------------------------------------------------------
# Line 85 — _cache_path_for_root when root is an existing file
# ---------------------------------------------------------------------------


def test_cache_path_for_root_uses_parent_directory_when_root_is_a_file(
    tmp_path: Path,
) -> None:
    """When a workspace folder points directly to a .yar file, the cache is
    placed beside that file (in its parent directory)."""
    yar = tmp_path / "single.yar"
    yar.write_text("rule single { condition: true }\n", encoding="utf-8")

    index = WorkspaceIndex()
    cache_path = index._cache_path_for_root(yar)

    # The file is inside tmp_path, so the cache must live under tmp_path/.yaraast/.
    assert cache_path == tmp_path / ".yaraast" / "lsp-workspace-index.json"


# ---------------------------------------------------------------------------
# Line 91 — _workspace_root_for_uri returns None for non-routable URIs
# ---------------------------------------------------------------------------


def test_workspace_root_for_uri_returns_none_for_non_file_uri(tmp_path: Path) -> None:
    """A URI that uses a scheme other than file:// (e.g. untitled://) cannot
    be resolved to a workspace root; the method must return None."""
    index = WorkspaceIndex()
    index.workspace_folders = [tmp_path]

    # "untitled://" contains "://" so uri_to_path returns None, exercising line 91.
    result = index._workspace_root_for_uri("untitled://buffer/scratch.yar")
    assert result is None


# ---------------------------------------------------------------------------
# Line 103->98 — _workspace_root_for_path picks the longest (deepest) root
# ---------------------------------------------------------------------------


def test_workspace_root_for_path_selects_deepest_matching_root(tmp_path: Path) -> None:
    """When two workspace folders both contain a path, the deeper one wins.
    The shorter root exercises the branch where root_length <= best_length."""
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)

    target = child / "target.yar"
    target.write_text("rule target { condition: true }\n", encoding="utf-8")

    index = WorkspaceIndex()
    # Register parent first so the shorter root is encountered before the longer one.
    index.workspace_folders = [parent, child]

    chosen_root = index._workspace_root_for_path(target)
    # The child root is longer (deeper) so it must win.
    assert chosen_root == child


# ---------------------------------------------------------------------------
# Lines 111-112 — _workspace_root_matches_path handles OSError from resolve()
# ---------------------------------------------------------------------------


def test_workspace_root_matches_path_returns_false_on_resolve_oserror(
    tmp_path: Path,
) -> None:
    """An extremely long (or otherwise bad) root path causes Path.resolve() to
    raise OSError on some platforms; the method must catch it and return False."""
    index = WorkspaceIndex()

    # A path name longer than the OS limit reliably triggers OSError on resolve.
    bad_root = Path("a" * 5000)
    real_path = (tmp_path / "real.yar").resolve()

    result = index._workspace_root_matches_path(real_path, bad_root)
    assert result is False


# ---------------------------------------------------------------------------
# Line 114 — _workspace_root_matches_path file-root exact-match branch
# ---------------------------------------------------------------------------


def test_workspace_root_matches_path_file_root_exact_match(tmp_path: Path) -> None:
    """When the workspace root is itself a file (not a directory), the method
    returns True only when the resolved path equals the resolved root exactly."""
    yar = tmp_path / "exact.yar"
    yar.write_text("rule exact { condition: true }\n", encoding="utf-8")
    other = tmp_path / "other.yar"
    other.write_text("rule other { condition: true }\n", encoding="utf-8")

    index = WorkspaceIndex()
    resolved_yar = yar.resolve()

    # Exact match: True.
    assert index._workspace_root_matches_path(resolved_yar, yar) is True
    # Different file: False (also exercises line 114 negative path).
    assert index._workspace_root_matches_path(other.resolve(), yar) is False


# ---------------------------------------------------------------------------
# Lines 135-137 — load() skips a cache file that contains invalid JSON
# ---------------------------------------------------------------------------


def test_load_skips_cache_with_invalid_json(tmp_path: Path) -> None:
    """A corrupted (non-parseable) cache file must be silently skipped; the
    index loads successfully with an empty symbol table."""
    cache_path = tmp_path / ".yaraast" / "lsp-workspace-index.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text("{ this is not valid json }", encoding="utf-8")

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert index.persisted_symbols == {}


# ---------------------------------------------------------------------------
# Line 142 — load() skips payload where raw_symbols is not a dict
# ---------------------------------------------------------------------------


def test_load_skips_payload_when_symbols_value_is_not_a_dict(tmp_path: Path) -> None:
    """When the top-level "symbols" key holds a list instead of a dict, the
    loader must skip it without raising."""
    _write_cache(
        tmp_path / ".yaraast" / "lsp-workspace-index.json",
        {"symbols": ["this", "is", "a", "list"]},
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert index.persisted_symbols == {}


# ---------------------------------------------------------------------------
# Line 145 — load() skips raw_symbols entries with wrong key/value types
# ---------------------------------------------------------------------------


def test_load_skips_raw_symbols_entry_with_non_list_symbols(tmp_path: Path) -> None:
    """When a symbols entry maps a URI to something that is not a list, that
    entry must be silently dropped."""
    _write_cache(
        tmp_path / ".yaraast" / "lsp-workspace-index.json",
        {"symbols": {"file:///bad.yar": "not-a-list"}},
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert index.persisted_symbols == {}


# ---------------------------------------------------------------------------
# Line 158 — _load_symbol_records skips entries that are not dicts
# ---------------------------------------------------------------------------


def test_load_symbol_records_skips_non_dict_symbol_entries(tmp_path: Path) -> None:
    """Non-object entries inside a symbol list (e.g. strings or ints) must be
    silently discarded; valid entries that follow must still be loaded."""
    uri = path_to_uri(tmp_path / "mixed.yar")
    valid_entry = {
        "name": "valid_rule",
        "kind": "rule",
        "uri": uri,
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 10},
        },
    }
    _write_cache(
        tmp_path / ".yaraast" / "lsp-workspace-index.json",
        {"symbols": {uri: ["not-a-dict", 42, valid_entry]}},
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    loaded = index.persisted_symbols.get(uri, [])
    assert len(loaded) == 1
    assert loaded[0].name == "valid_rule"


# ---------------------------------------------------------------------------
# Lines 186-187 — save() survives OSError when writing the cache file
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="chmod is not reliable on Windows")
def test_save_logs_and_continues_on_oserror(tmp_path: Path) -> None:
    """When the cache directory cannot be written to (no write permission),
    save() must not raise; it logs the error and returns normally."""
    yar = tmp_path / "locked.yar"
    yar.write_text("rule locked { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(yar)

    cache_dir = tmp_path / ".yaraast"
    cache_dir.mkdir(parents=True)

    # Remove write permission from the cache directory so mkdir/write fail.
    cache_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        index = WorkspaceIndex()
        index.workspace_folders = [tmp_path]
        index.persisted_symbols[uri] = [_make_symbol("locked", uri)]

        # Must not raise despite OSError.
        index.save()
    finally:
        cache_dir.chmod(stat.S_IRWXU)


def test_load_and_save_skip_symlinked_cache_dir_outside_workspace_root(
    tmp_path: Path,
) -> None:
    """A symlinked .yaraast cache directory that points outside the workspace
    must be ignored for both reading and writing."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    payload_text = json.dumps(
        {
            "symbols": {
                path_to_uri(root / "alpha.yar"): [
                    {
                        "name": "alpha",
                        "kind": "rule",
                        "uri": path_to_uri(root / "alpha.yar"),
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": 5},
                        },
                    }
                ]
            }
        },
        indent=2,
    )
    (outside / "lsp-workspace-index.json").write_text(payload_text, encoding="utf-8")
    (root / ".yaraast").symlink_to(outside, target_is_directory=True)

    index = WorkspaceIndex()
    index.workspace_folders = [root]
    index.load()
    assert index.persisted_symbols == {}

    uri = path_to_uri(root / "alpha.yar")
    index.persisted_symbols[uri] = [_make_symbol("alpha", uri)]
    index.save()

    assert (outside / "lsp-workspace-index.json").read_text(encoding="utf-8") == payload_text


# ---------------------------------------------------------------------------
# Line 221 — search_records skips URIs in the excluded set
# ---------------------------------------------------------------------------


def test_search_records_skips_excluded_uris() -> None:
    """Symbols belonging to URIs in the exclude_uris set must be absent from
    the results; symbols from other URIs must still be returned."""
    uri_a = "file:///a.yar"
    uri_b = "file:///b.yar"

    index = WorkspaceIndex()
    index.persisted_symbols[uri_a] = [_make_symbol("rule_a", uri_a)]
    index.persisted_symbols[uri_b] = [_make_symbol("rule_b", uri_b)]

    results = index.search_records("", exclude_uris={uri_a})

    names = {r.name for r in results}
    assert "rule_a" not in names
    assert "rule_b" in names


def test_search_records_non_matching_query_skips_symbol(tmp_path: Path) -> None:
    """When a non-empty query is provided, symbols whose names do not contain
    the query substring must be skipped (exercises the continue on line 221)."""
    uri = "file:///mixed.yar"

    index = WorkspaceIndex()
    index.persisted_symbols[uri] = [
        _make_symbol("alpha_rule", uri),
        _make_symbol("beta_rule", uri),
        _make_symbol("gamma_rule", uri),
    ]

    # Query that matches only "beta"; alpha and gamma must be skipped via the
    # inner-loop continue that guards the non-matching name branch.
    results = index.search_records("beta")
    assert len(results) == 1
    assert results[0].name == "beta_rule"

    # Verify no matches returns empty, not an error.
    assert index.search_records("zzzzzz") == []

    # Verify the public search() wrapper also filters correctly.
    symbol_infos = index.search("beta")
    assert len(symbol_infos) == 1
    assert symbol_infos[0].name == "beta_rule"


# ---------------------------------------------------------------------------
# Lines 231-232 — iter_candidate_files when workspace folder is a YARA file
# ---------------------------------------------------------------------------


def test_iter_candidate_files_includes_yara_file_root_directly(tmp_path: Path) -> None:
    """When a workspace folder points to a .yar file rather than a directory,
    that file must appear in the candidate list."""
    yar = tmp_path / "standalone.yar"
    yar.write_text("rule standalone { condition: true }\n", encoding="utf-8")

    index = WorkspaceIndex()
    index.workspace_folders = [yar]

    candidates = index.iter_candidate_files()
    assert yar in candidates


def test_iter_candidate_files_excludes_non_yara_file_root(tmp_path: Path) -> None:
    """When a workspace folder points to a file with a non-YARA suffix, it
    must not appear in the candidate list (exercises the suffix guard)."""
    txt = tmp_path / "notes.txt"
    txt.write_text("rule notes { condition: true }\n", encoding="utf-8")

    index = WorkspaceIndex()
    index.workspace_folders = [txt]

    candidates = index.iter_candidate_files()
    assert txt not in candidates


# ---------------------------------------------------------------------------
# Line 234 — iter_candidate_files skips entries that are neither file nor dir
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.name == "nt", reason="symlinks to missing targets behave differently on Windows"
)
def test_iter_candidate_files_skips_path_that_exists_but_is_not_file_or_dir(
    tmp_path: Path,
) -> None:
    """A path that exists (path_exists returns True) but is neither a regular
    file nor a directory (e.g. a broken symlink that resolves via os.path but
    fails is_file/is_dir) must be silently skipped."""
    broken_link = tmp_path / "broken"
    broken_link.symlink_to(tmp_path / "nonexistent_target")

    index = WorkspaceIndex()
    # Use a folder containing a real YARA file plus the broken symlink as a
    # second workspace folder so we can observe that only the real file appears.
    yar = tmp_path / "real.yar"
    yar.write_text("rule real { condition: true }\n", encoding="utf-8")

    index.workspace_folders = [broken_link, tmp_path]

    candidates = index.iter_candidate_files()
    # The real file must be discovered via tmp_path.
    assert yar in candidates
    # The broken link must not appear as a candidate itself.
    assert broken_link not in candidates


# ---------------------------------------------------------------------------
# Lines 238-239 — iter_candidate_files handles OSError from rglob
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="chmod is not reliable on Windows")
def test_iter_candidate_files_skips_rglob_oserror(tmp_path: Path) -> None:
    """When rglob raises OSError (e.g. an unreadable subdirectory), the
    method must log and continue rather than propagating the exception."""
    locked_dir = tmp_path / "locked"
    locked_dir.mkdir()
    yar = locked_dir / "hidden.yar"
    yar.write_text("rule hidden { condition: true }\n", encoding="utf-8")

    # Remove read+execute permission so rglob cannot traverse the directory.
    locked_dir.chmod(0)
    try:
        index = WorkspaceIndex()
        index.workspace_folders = [tmp_path]

        # Must not raise; returns what it can (may be empty due to locked dir).
        candidates = index.iter_candidate_files()
        assert isinstance(candidates, list)
    finally:
        locked_dir.chmod(stat.S_IRWXU)
