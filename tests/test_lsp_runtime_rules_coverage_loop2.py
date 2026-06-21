"""
Additional coverage tests for yaraast/lsp/runtime_rules.py (loop 2).

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Prior file tests/test_lsp_runtime_rules_coverage_loop.py reached 94.41%, leaving
five groups of uncovered lines: 120, 147-149, 184-186, and 199.

Investigation (confirmed by direct execution and source analysis):

  Line 120 (continue in find_rule_reference_records):
    The inner call ``doc.rule_reference_records(rule_name,
    include_declaration=include_declaration)`` passes the same
    ``include_declaration`` flag directly to the document layer.  When
    ``include_declaration=False``, the document layer already filters out the
    declaration record before yielding (document_query_references.py line 293).
    The outer ``continue`` at line 120 can therefore never be reached: the
    record that would trigger it is stripped one layer below.

  Lines 147-149, 184-186 (except Exception blocks):
    Both functions call ``runtime.get_document(document_uri)`` inside a
    try/except.  However, ``LspRuntime.get_document`` (runtime.py lines 323-327)
    catches all exceptions internally and returns None — it never propagates.
    The only exception path that escapes ``get_document`` is a ``TypeError``
    raised by ``_require_document_uri`` when the URI is not a string, but any
    non-string ``document_uri`` is eliminated before the ``get_document`` call
    by the ``uri_to_path`` guard (line 142 / 179): ``uri_to_path`` returns None
    for non-strings, triggering an early ``return []``.  No real execution path
    can therefore reach the ``except`` clauses at lines 147-149 / 184-186.

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

This file adds one net-new covered line (199) and documents the three groups of
structurally dead lines with concrete evidence.
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
# Dead-code evidence: line 120 in find_rule_reference_records
#
# The ``continue`` at line 120 is supposed to skip the declaration record when
# ``include_declaration=False``.  However, the call to
# ``doc.rule_reference_records(rule_name, include_declaration=include_declaration)``
# passes the flag through to the document layer, which already filters out the
# declaration (document_query_references.py line 293).  The record that would
# trigger line 120 is never yielded.
#
# The tests below demonstrate this with a two-file workspace where one file
# defines the rule and one references it.  Regardless of the ``include_declaration``
# flag, the declaration record never arrives at line 120.  These tests add
# behavioural coverage of the surrounding path (lines 113-119, 121-128) while
# confirming the logical structure.
# ---------------------------------------------------------------------------


def test_find_rule_reference_records_include_declaration_false_yields_only_uses(
    tmp_path: Path,
) -> None:
    """Surroundings of line 120: include_declaration=False must exclude the declaration.

    This test verifies the end-to-end behaviour of the include_declaration=False
    path.  Line 120 itself remains uncovered because the document layer filters
    the declaration before it reaches the outer loop — the guard at 120 is dead.
    """
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
# Dead-code evidence: lines 147-149 in find_rule_reference_records_in_document
# and lines 184-186 in get_rule_link_records_for_document
#
# Both functions wrap ``runtime.get_document(document_uri)`` in a try/except.
# LspRuntime.get_document (runtime.py:323-327) catches all exceptions internally
# and returns None — it never propagates.  The ``except Exception`` clauses at
# 147-149 and 184-186 are therefore unreachable through normal use.
#
# The only exception that can escape get_document is a TypeError from
# _require_document_uri when the URI is not a string, but a non-string URI is
# eliminated before get_document is called because uri_to_path returns None,
# causing an early ``return []``.
#
# The tests below exercise the maximum reachable prefix of the try block: they
# confirm the function calls get_document and handles a None return correctly
# (line 150 / 187).  This is the closest real construction possible.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    __import__("os").getuid() == 0,
    reason="root bypasses file permission checks",
)
def test_find_rule_reference_records_in_document_get_document_returns_none_for_unreadable(
    tmp_path: Path,
) -> None:
    """Lines 145-151 prefix: get_document returns None for an unreadable file.

    This test reaches the ``try`` block at line 145, executes
    ``runtime.get_document(document_uri)`` (which catches PermissionError
    internally and returns None), then hits ``if doc is None: return []`` at
    line 150.  The ``except`` clause at lines 147-149 is not reached because
    get_document swallows all I/O errors.

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
    """Lines 182-188 prefix: get_document returns None for an unreadable file.

    Mirrors the test above for get_rule_link_records_for_document.  The
    ``try`` block at line 182 is entered; get_document catches PermissionError
    internally and returns None; ``if doc is None: return []`` at line 187 is
    hit.  The ``except`` at lines 184-186 is not reached.
    """
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
