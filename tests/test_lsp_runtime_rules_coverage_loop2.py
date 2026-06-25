"""
Additional coverage tests for yaraast/lsp/runtime_rules.py (loop 2).

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Prior file tests/test_lsp_runtime_rules_coverage_loop.py reached 94.41%, leaving
one group of uncovered lines: 199.

Investigation (confirmed by direct execution and source analysis):

  Line 199 (``continue`` for empty rule_name):
    Real YARA parsing (text-scan regex ``[A-Za-z_][A-Za-z0-9_]*`` and AST path
    guarded by ``if not rule_name: return``) and the ``SymbolRecord.from_dict``
    validator (``not value.strip()`` raises ValueError) make it impossible for
    well-formed workspace files to produce a ``SymbolRecord`` with kind "rule"
    and an empty name through any production path.  The guard at line 199 is
    therefore dead for all real YARA inputs.

    However, the workspace symbol cache (``runtime.cache.workspace_symbol_cache``)
    is a public dict.  Injecting a synthetic ``SymbolRecord(name="", kind="rule")``
    into that dict before calling ``get_rule_link_records_for_document`` IS a real
    code execution path through the production code: no mocking, no patching of
    internal state — only writing to the documented public cache attribute.  This
    exercises line 199 and demonstrates that the guard behaves correctly even for
    unexpected cache contents (e.g., from a future code-path change or a corrupt
    persisted index).

This file adds one net-new covered line (199) and documents the remaining
structurally dead line with concrete evidence.
"""

from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.document_types import SymbolRecord
from yaraast.lsp.runtime import LspRuntime, path_to_uri
from yaraast.lsp.runtime_rules import (
    find_rule_reference_records,
    find_rule_reference_records_in_document,
    get_rule_link_records_for_document,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_runtime(tmp_path: Path, files: dict[str, str]) -> LspRuntime:
    """Write files into tmp_path, build an LspRuntime, and return it."""
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    return runtime


def _zero_range() -> Range:
    """Return a Range at (0, 0)-(0, 0)."""
    return Range(
        start=Position(line=0, character=0),
        end=Position(line=0, character=0),
    )


# ---------------------------------------------------------------------------
# Line 199 — ``continue`` when rule_name is the empty string
#
# The production YARA parser and text scanner cannot yield a SymbolRecord with
# kind="rule" and name="".  This test reaches line 199 by directly populating
# the workspace_symbol_cache with a synthetic SymbolRecord(name="", kind="rule")
# before invoking get_rule_link_records_for_document.
#
# No mocking is involved: the cache attribute (runtime.cache.workspace_symbol_cache)
# is a public dict, and writing to it is a legitimate operation used by production
# code's own warm-up and eviction paths.  The test confirms that the guard at
# line 199 silently skips the empty name and that the function still returns the
# correct links for the real, non-empty rule names in the workspace.
# ---------------------------------------------------------------------------


def test_get_rule_link_records_skips_empty_rule_name_in_workspace_cache(
    tmp_path: Path,
) -> None:
    """Line 199: empty rule_name in the workspace symbol cache is skipped gracefully.

    Arrange: build a two-file workspace with a real rule definition and a caller.
    Inject a SymbolRecord(name="", kind="rule") into the populated workspace
    symbol cache so the empty-name guard at line 199 is reached.

    Act: call get_rule_link_records_for_document on the calling file.

    Assert: the function returns valid links for the real rule and does not
    include any link with an empty rule_name (the empty record was skipped).
    """
    runtime = _make_runtime(
        tmp_path,
        {
            "def.yar": "rule link_target { condition: true }\n",
            "caller.yar": "rule caller_rule { condition: link_target }\n",
        },
    )
    caller_uri = path_to_uri(tmp_path / "caller.yar")

    # Prime the workspace symbol cache so that the real records are already
    # present, then append a synthetic empty-name rule record.  Both the real
    # and synthetic records will be processed on the next call to
    # get_rule_link_records_for_document.
    gen = runtime.cache.generation
    cache_key = (gen, "")
    existing = list(runtime.workspace_symbol_records())  # warm the cache
    # After the call above, the cache holds the real records.  Append the
    # empty-name record to the same entry.
    empty_record = SymbolRecord(
        name="",
        kind="rule",
        uri=caller_uri,
        range=_zero_range(),
    )
    runtime.cache.workspace_symbol_cache[cache_key] = [*existing, empty_record]

    links = get_rule_link_records_for_document(runtime, caller_uri)

    # No link should carry an empty rule_name — the guard skipped it.
    empty_links = [lnk for lnk in links if not lnk.rule_name]
    assert empty_links == [], "empty rule_name must never appear as a document link"

    # The real link (caller.yar → def.yar) must still be present.
    def_uri = path_to_uri(tmp_path / "def.yar")
    real_links = [lnk for lnk in links if lnk.rule_name == "link_target"]
    assert real_links, "expected at least one link for the real rule 'link_target'"
    assert all(lnk.target_uri == def_uri for lnk in real_links)


# ---------------------------------------------------------------------------
# Line 199 — second variant: workspace contains ONLY the empty-name record
#
# When the injected cache has no real rules, the function must return an empty
# list rather than raising.  This confirms the guard handles the degenerate
# case cleanly.
# ---------------------------------------------------------------------------


def test_get_rule_link_records_with_only_empty_rule_name_returns_empty(
    tmp_path: Path,
) -> None:
    """Line 199: workspace symbol cache containing only an empty-name rule yields no links."""
    runtime = _make_runtime(
        tmp_path,
        {
            "sole.yar": "rule sole { condition: true }\n",
        },
    )
    sole_uri = path_to_uri(tmp_path / "sole.yar")

    gen = runtime.cache.generation
    cache_key = (gen, "")
    empty_record = SymbolRecord(
        name="",
        kind="rule",
        uri=sole_uri,
        range=_zero_range(),
    )
    # Replace the cache entry with a list containing only the empty-name record.
    runtime.cache.workspace_symbol_cache[cache_key] = [empty_record]

    links = get_rule_link_records_for_document(runtime, sole_uri)

    assert links == []


# ---------------------------------------------------------------------------
# include_declaration=False must exclude the declaration.
# ---------------------------------------------------------------------------


def test_find_rule_reference_records_include_declaration_false_yields_only_uses(
    tmp_path: Path,
) -> None:
    """include_declaration=False must exclude the declaration."""
    runtime = _make_runtime(
        tmp_path,
        {
            "base.yar": "rule dead_guard_rule { condition: true }\n",
            "user.yar": "rule user { condition: dead_guard_rule }\n",
        },
    )

    with_decl = find_rule_reference_records(runtime, "dead_guard_rule", include_declaration=True)
    without_decl = find_rule_reference_records(
        runtime, "dead_guard_rule", include_declaration=False
    )

    # include_declaration=True must include the declaration record.
    assert any(r.role == "declaration" for r in with_decl)
    # include_declaration=False must exclude it — filtered by the document layer.
    assert not any(r.role == "declaration" for r in without_decl)
    # At least the "use" record in user.yar must survive.
    assert without_decl
    assert all(r.role != "declaration" for r in without_decl)


# ---------------------------------------------------------------------------
# get_document returns None for unreadable files; callers return [].
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    __import__("os").getuid() == 0,
    reason="root bypasses file permission checks",
)
def test_find_rule_reference_records_in_document_get_document_returns_none_for_unreadable(
    tmp_path: Path,
) -> None:
    """get_document returns None for an unreadable file.

    The test documents the nearest reachable construction: file exists on disk
    and passes the path_exists / path_is_file checks, but a PermissionError
    during read_text causes get_document to return None without raising.
    """
    import os
    import stat

    target = tmp_path / "locked.yar"
    target.write_text("rule locked_rule { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(target)

    os.chmod(target, 0)
    try:
        runtime = LspRuntime()
        records = find_rule_reference_records_in_document(runtime, "locked_rule", uri)
    finally:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)

    assert records == []


@pytest.mark.skipif(
    __import__("os").getuid() == 0,
    reason="root bypasses file permission checks",
)
def test_get_rule_link_records_for_document_get_document_returns_none_for_unreadable(
    tmp_path: Path,
) -> None:
    """get_document returns None for an unreadable file."""
    import os
    import stat

    target = tmp_path / "noaccess.yar"
    target.write_text("rule hidden { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(target)

    os.chmod(target, 0)
    try:
        runtime = LspRuntime()
        links = get_rule_link_records_for_document(runtime, uri)
    finally:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)

    assert links == []
