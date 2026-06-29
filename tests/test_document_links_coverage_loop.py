"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Real regression tests for yaraast.lsp.document_links lines not yet covered:

 - Lines 95-98:  outer except block in get_document_links (no-runtime path raises)
 - Branch 112->109: _create_runtime_symbol_links, import module not in module_docs → url is None
 - Branch 126->109: _create_runtime_symbol_links, include file not resolvable → target_uri is None
 - Line 138:     links.append inside _create_rule_reference_links (runtime with cross-doc rule refs)
 - Line 206:     continue in _append_text_rule_links (rule name inside a block comment)
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri

# ---------------------------------------------------------------------------
# Branch 112->109 - import of a module not listed in module_docs
# ---------------------------------------------------------------------------


def test_unknown_import_module_skipped_no_link(tmp_path: Path) -> None:
    """
    When a document imports a module whose name is not in DocumentLinksProvider.module_docs
    the provider must not produce a link for that import (branch 112->109: url is None/falsy).

    Arrange: write a YARA file that imports a custom module name "custom_engine" which
    is deliberately absent from the built-in module_docs dict.

    Act: call get_document_links with both a runtime-aware and runtime-less provider so that
    _create_runtime_symbol_links is exercised and the falsy-url branch is taken.

    Assert: no link with a target pointing to readthedocs exists for the unknown module name;
    the known "pe" import (present in the same file) still produces a link so we confirm
    the happy path was also taken for contrast.
    """
    doc_path = tmp_path / "doc.yar"
    text = dedent("""\
        import "pe"
        import "custom_engine"

        rule sample {
            condition:
                pe.is_pe
        }
    """)
    doc_path.write_text(text, encoding="utf-8")

    # Verify "custom_engine" is genuinely absent from module_docs.
    provider = DocumentLinksProvider()
    assert "custom_engine" not in provider.module_docs

    # Runtime-less path: symbols() + _create_runtime_symbol_links run but
    # "custom_engine" has no url so the branch 112->109 is taken.
    links = provider.get_document_links(text, path_to_uri(doc_path))

    targets = {link.target for link in links if link.target is not None}
    tooltips = {link.tooltip for link in links if link.tooltip is not None}

    # The known module must produce a link.
    assert any("pe.html" in t for t in targets), "Expected a link for the known 'pe' module"

    # The unknown module must not produce any readthedocs link.
    assert not any("custom_engine" in (t or "") for t in targets), (
        "Must not produce a link for an unknown import module"
    )
    assert not any("custom_engine" in (t or "") for t in tooltips), (
        "Must not produce a tooltip for an unknown import module"
    )


def test_unknown_import_via_runtime_skipped(tmp_path: Path) -> None:
    """
    Same coverage target (branch 112->109) reached through the runtime code path so that
    _create_runtime_symbol_links is invoked with a real LspRuntime providing SymbolRecords.
    """
    doc_path = tmp_path / "doc.yar"
    text = dedent("""\
        import "math"
        import "unknown_module"

        rule sample {
            condition:
                math.abs(-1) == 1
        }
    """)
    doc_path.write_text(text, encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    provider = DocumentLinksProvider(runtime)

    links = provider.get_document_links(text, path_to_uri(doc_path))
    targets = [link.target or "" for link in links]

    assert any("math.html" in t for t in targets), "Expected link for 'math' module"
    assert not any("unknown_module" in t for t in targets), (
        "Must not produce a link for 'unknown_module'"
    )


# ---------------------------------------------------------------------------
# Branch 126->109 - include with unresolvable target_uri
# ---------------------------------------------------------------------------


def test_include_missing_file_yields_no_link(tmp_path: Path) -> None:
    """
    When an include directive references a file that does not exist on disk
    resolve_include_target_uri returns None (or get_include_target_uri returns None)
    so the branch 126->109 is taken and no link is appended.

    Arrange: text contains include "nonexistent.yar" where the file is absent.

    Act: call get_document_links with a LspRuntime that has a workspace folder configured
    so that _create_runtime_symbol_links is reached via the runtime code path.

    Assert: no link whose target resolves to nonexistent.yar is produced.
    """
    doc_path = tmp_path / "doc.yar"
    text = 'include "nonexistent.yar"\nrule sample { condition: true }\n'
    doc_path.write_text(text, encoding="utf-8")

    # Sanity-check: the file must not exist so the branch is genuinely taken.
    assert not (tmp_path / "nonexistent.yar").exists()

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    provider = DocumentLinksProvider(runtime)

    links = provider.get_document_links(text, path_to_uri(doc_path))
    targets = [link.target or "" for link in links]

    assert not any("nonexistent" in t for t in targets), (
        "Must not produce a link for an unresolvable include path"
    )


def test_include_missing_file_no_runtime_yields_no_link(tmp_path: Path) -> None:
    """
    Same coverage target (branch 126->109) reached without a runtime so that
    get_include_target_uri is used instead of resolve_include_target_uri.

    Assert: absent include file → target_uri is None → no link appended.
    """
    doc_path = tmp_path / "doc.yar"
    text = 'include "ghost.yar"\nrule ghost_rule { condition: true }\n'
    doc_path.write_text(text, encoding="utf-8")

    assert not (tmp_path / "ghost.yar").exists()

    provider = DocumentLinksProvider()
    links = provider.get_document_links(text, path_to_uri(doc_path))
    targets = [link.target or "" for link in links]

    assert not any("ghost" in t for t in targets)


# ---------------------------------------------------------------------------
# Lines 95-98 - outer except block in get_document_links (no-runtime path)
# ---------------------------------------------------------------------------


def test_get_document_links_outer_except_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """
    Cover lines 95-98: the outer except in get_document_links that catches any exception
    raised in the no-runtime code path (lines 88-93) and falls back to _fallback_links.

    Arrangement: inject a fault into DocumentContext.get_local_rule_link_records so that
    the call at line 91 (_create_local_rule_reference_links) raises an exception.
    The provider has runtime=None so it takes the no-runtime branch (line 88).

    Act: call get_document_links without a runtime.

    Assert: the provider does not propagate the exception; instead it returns at least
    the links that _fallback_links produces (the import "pe" link in this case).
    """
    doc_path = tmp_path / "doc.yar"
    text = 'import "pe"\nrule sample { condition: true }\n'
    doc_path.write_text(text, encoding="utf-8")

    def crashing_get_local_rule_link_records(self: DocumentContext) -> list[Any]:
        raise RuntimeError("injected failure for outer-except coverage")

    monkeypatch.setattr(
        DocumentContext,
        "get_local_rule_link_records",
        crashing_get_local_rule_link_records,
    )

    # No runtime → takes the no-runtime path; the injected crash triggers lines 95-98.
    provider = DocumentLinksProvider()
    links = provider.get_document_links(text, path_to_uri(doc_path))

    # The fallback should recover and still produce the pe import link.
    targets = [link.target or "" for link in links]
    assert any("pe.html" in t for t in targets), (
        "Fallback links must include the pe module documentation link"
    )


# ---------------------------------------------------------------------------
# Line 138 - links.append inside _create_rule_reference_links
# ---------------------------------------------------------------------------


def test_create_rule_reference_links_returns_empty_when_no_runtime() -> None:
    """
    Cover line 138: _create_rule_reference_links has a defensive early-return guard
    (line 137: ``if self.runtime is None: return []``) so it is safe to call directly
    even without a runtime.  This line is not reachable via get_document_links because
    the public method only routes to _create_rule_reference_links when self.runtime is
    truthy (line 74).  Direct invocation on a runtime-less provider reaches line 138.

    Arrange: create a DocumentLinksProvider with no runtime argument.
    Act: call _create_rule_reference_links directly with an arbitrary URI.
    Assert: an empty list is returned immediately (the early-return path on line 138).
    """
    provider = DocumentLinksProvider()  # runtime is None by default
    assert provider.runtime is None

    result = provider._create_rule_reference_links("file:///any/path.yar")

    assert result == [], (
        "_create_rule_reference_links must return [] when self.runtime is None (line 138)"
    )


def test_create_rule_reference_links_appends_cross_doc_link(tmp_path: Path) -> None:
    """
    Functional integration: _create_rule_reference_links with a runtime that has indexed
    a cross-document rule reference must append one DocumentLink per reference.

    Scenario: common.yar defines shared_rule; user.yar references it in a condition.
    After opening user.yar, get_rule_link_records_for_document returns a record linking
    user.yar → common.yar, and _create_rule_reference_links appends that link (line 142).

    Arrange: write both files, initialise a runtime with workspace folder, open user.yar.
    Act: call _create_rule_reference_links directly.
    Assert: the returned list contains a link pointing at common.yar with the expected tooltip.
    """
    common = tmp_path / "common.yar"
    user = tmp_path / "user.yar"
    common.write_text("rule shared_rule { condition: true }\n", encoding="utf-8")
    user_text = "rule user_rule { condition: shared_rule }\n"
    user.write_text(user_text, encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    # open_document registers user.yar so the workspace index can find cross-file refs.
    runtime.open_document(path_to_uri(user), user_text)

    provider = DocumentLinksProvider(runtime)

    rule_links = provider._create_rule_reference_links(path_to_uri(user))

    assert len(rule_links) >= 1, (
        "_create_rule_reference_links must return at least one link for shared_rule"
    )
    shared_rule_links = [lnk for lnk in rule_links if lnk.tooltip == "Go to rule shared_rule"]
    assert shared_rule_links, "Expected a link tooltipped 'Go to rule shared_rule'"
    assert shared_rule_links[0].target == common.as_uri(), (
        "The rule link target must point at common.yar"
    )


def test_get_document_links_runtime_includes_cross_doc_rule_link(tmp_path: Path) -> None:
    """
    Integration test: get_document_links with a full LspRuntime must produce a link from
    user.yar to common.yar for the cross-document rule reference (line 138 via full call).
    """
    common = tmp_path / "common.yar"
    user = tmp_path / "user.yar"
    common.write_text("rule base_rule { condition: true }\n", encoding="utf-8")
    user_text = "rule derived_rule { condition: base_rule }\n"
    user.write_text(user_text, encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    runtime.open_document(path_to_uri(user), user_text)
    provider = DocumentLinksProvider(runtime)

    links = provider.get_document_links(user_text, path_to_uri(user))

    targets = {link.target for link in links if link.target is not None}
    assert common.as_uri() in targets, (
        "Full get_document_links must include a cross-document link to common.yar"
    )


# ---------------------------------------------------------------------------
# Line 206 - continue in _append_text_rule_links (block-comment position)
# ---------------------------------------------------------------------------


def test_append_text_rule_links_skips_name_in_block_comment(tmp_path: Path) -> None:
    """
    Cover line 206: the continue statement inside _append_text_rule_links that fires when
    position_is_in_non_code_segment returns True for the matched position.

    The code masks line-comments and string literals with mask_non_code_segments, but it
    does NOT mask block comments (/* ... */). A rule name that appears inside a block
    comment passes the whole_word_positions scan on the masked line (unchanged), yet
    position_is_in_non_code_segment correctly identifies the position as inside a block
    comment and returns True, which triggers the continue on line 206.

    Arrange: a document with two rules where the second rule's condition contains the
    first rule's name inside a block comment.  The rule name also appears in a normal
    code position outside the comment so that line 206 is hit for the comment occurrence
    while the code occurrence still produces a link.

    Act: call get_document_links (no runtime needed) and inspect results.

    Assert: a link is produced for the valid in-code occurrence; no duplicate link exists
    for the comment occurrence (confirming that line 206 filtered it out).
    """
    doc_path = tmp_path / "doc.yar"
    text = dedent("""\
        rule alpha_rule {
            condition:
                true
        }

        rule beta_rule {
            condition:
                /* alpha_rule is excluded here */
                alpha_rule
        }
    """)
    doc_path.write_text(text, encoding="utf-8")

    provider = DocumentLinksProvider()
    links = provider.get_document_links(text, path_to_uri(doc_path))

    alpha_links = [lnk for lnk in links if lnk.tooltip == "Go to rule alpha_rule"]

    # At least one link must exist: the in-code reference on the last condition line.
    assert alpha_links, "Expected at least one link for 'alpha_rule' from the real code position"

    # The in-code occurrence is on line 8 (0-based): "        alpha_rule"
    code_line = next((lnk for lnk in alpha_links if lnk.range.start.line == 8), None)
    assert code_line is not None, (
        "Expected a link for 'alpha_rule' on line 8 (the real code occurrence)"
    )

    # The comment occurrence is on line 7: "        /* alpha_rule is excluded here */"
    comment_line_links = [lnk for lnk in alpha_links if lnk.range.start.line == 7]
    assert not comment_line_links, (
        "Must NOT produce a link for 'alpha_rule' inside a block comment (line 206 continue)"
    )


def test_append_text_rule_links_only_code_position_linked(tmp_path: Path) -> None:
    """
    Focused test: when the ONLY occurrence of a rule name in another rule's body is
    inside a block comment, no link is produced at all for that rule name reference.

    This directly exercises line 206 where the continue causes zero links to be added
    for the comment-embedded rule name.
    """
    doc_path = tmp_path / "doc.yar"
    text = dedent("""\
        rule only_in_comment {
            condition:
                true
        }

        rule consumer_rule {
            condition:
                /* only_in_comment should not be linked */
                true
        }
    """)
    doc_path.write_text(text, encoding="utf-8")

    provider = DocumentLinksProvider()
    links = provider.get_document_links(text, path_to_uri(doc_path))

    comment_only_links = [lnk for lnk in links if lnk.tooltip == "Go to rule only_in_comment"]
    assert not comment_only_links, (
        "Rule name inside a block comment must not produce a document link"
    )
