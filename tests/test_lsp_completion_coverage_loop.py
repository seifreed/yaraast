# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage tests for yaraast/lsp/completion.py targeting missing branches.

Missing lines from baseline (90.78%) at the start of this session:
  104->113  _keywords_for_document: non-AUTO language mode skips auto-detection block
  140-142   _get_module_member_completions: dotted module_name with and without access_chain
  157       _get_workspace_rule_completions: early return when self.runtime is None
  176-177   _get_workspace_rule_completions: exception handler swallows workspace errors

Structurally unreachable lines (documented, not tested):
  166->165  get_rule_names() never yields empty strings: YARA rule names are always
            non-empty identifiers extracted by the real tree-sitter parser.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from lsprotocol.types import Position
import pytest

from yaraast.lsp.completion import CompletionProvider
from yaraast.lsp.completion_helpers import get_keywords_for_mode
from yaraast.lsp.document_types import LanguageMode, RuntimeConfig
from yaraast.lsp.runtime import LspRuntime, path_to_uri


def _pos(line: int, character: int) -> Position:
    return Position(line=line, character=character)


# ---------------------------------------------------------------------------
# _keywords_for_document: non-AUTO mode skips the dialect-detection block
# (line 104->113: mode.value != "auto" so the inner if is skipped)
# ---------------------------------------------------------------------------


class TestKeywordsForDocumentNonAutoMode:
    """_keywords_for_document must return dialect keywords when runtime is
    configured with an explicit (non-AUTO) LanguageMode.  In that case the
    method must skip the auto-detection mapping block and call
    get_keywords_for_mode directly with the already-resolved mode.
    """

    def _make_runtime_with_mode(self, mode: LanguageMode) -> tuple[LspRuntime, str]:
        config = RuntimeConfig(language_mode=mode)
        runtime = LspRuntime(config=config)
        uri = "file:///tmp/kw_mode_test.yar"
        text = "rule r { condition: true }"
        runtime.open_document(uri, text)
        return runtime, uri

    def test_yara_x_mode_returns_yarax_keyword_set(self) -> None:
        # Arrange: runtime explicitly set to YARA_X; 'with', 'lambda', 'match'
        # are YARA-X-only keywords absent from the base YARA keyword list.
        runtime, uri = self._make_runtime_with_mode(LanguageMode.YARA_X)
        provider = CompletionProvider(runtime)
        text = "rule r { condition: true }"
        expected = get_keywords_for_mode(LanguageMode.YARA_X)

        # Act
        actual = provider._keywords_for_document(text, uri)

        # Assert: must be exactly the YARA-X keyword list
        assert actual == expected
        assert "with" in actual
        assert "match" in actual
        assert "lambda" in actual

    def test_yara_mode_returns_yara_keyword_set(self) -> None:
        # Arrange: YARA mode - no YARA-X extensions expected
        runtime, uri = self._make_runtime_with_mode(LanguageMode.YARA)
        provider = CompletionProvider(runtime)
        text = "rule r { condition: true }"
        expected = get_keywords_for_mode(LanguageMode.YARA)

        # Act
        actual = provider._keywords_for_document(text, uri)

        # Assert
        assert actual == expected
        assert "with" not in actual

    def test_yaral_mode_returns_yaral_keyword_set(self) -> None:
        # Arrange: YARA-L mode
        runtime, uri = self._make_runtime_with_mode(LanguageMode.YARA_L)
        provider = CompletionProvider(runtime)
        text = "rule r { condition: true }"
        expected = get_keywords_for_mode(LanguageMode.YARA_L)

        # Act
        actual = provider._keywords_for_document(text, uri)

        # Assert: YARA-L keywords contain 'events' which YARA/YARA-X do not
        assert actual == expected
        assert "events" in actual

    def test_non_auto_mode_completions_reflect_dialect(self) -> None:
        # Integration: get_completions uses _keywords_for_document internally.
        # With YARA_X mode, the condition context must include YARA-X-only
        # keywords such as 'with'.
        # Multi-line text is required; analyze_context only returns "condition"
        # when the cursor is inside a rule body after 'condition:'.
        runtime, uri = self._make_runtime_with_mode(LanguageMode.YARA_X)
        provider = CompletionProvider(runtime)
        # Line 0: 'rule r {'  Line 1: '  condition:'  Line 2: cursor in body
        text = "rule r {\n  condition:\n    "
        pos = _pos(2, 4)

        # Act
        result = provider.get_completions(text, pos, uri)

        labels = {item.label for item in result.items}
        # 'with' is in YARA-X keywords but absent from base YARA keywords
        assert "with" in labels


# ---------------------------------------------------------------------------
# _get_module_member_completions: dotted module_name branches (lines 139-142)
# ---------------------------------------------------------------------------


class TestModuleMemberCompletionsDottedName:
    """_get_module_member_completions accepts a dotted module_name such as
    'pe.rich_signature'.  In that case it extracts the chain portion after
    the root module and passes it to build_module_member_completions.

    Lines 139-140: dotted module_name triggers chain extraction.
    Lines 141-142: non-empty access_chain is merged with the extracted chain.

    These branches are only reachable via direct method calls because
    get_current_module (used by get_completions) always returns just the
    root identifier without sub-field suffixes.
    """

    def test_dotted_module_name_without_access_chain_extracts_sub_field(self) -> None:
        # Arrange: 'pe.rich_signature' has a dot; the method must split it into
        # root='pe' and chain='rich_signature', then look up pe.rich_signature members.
        provider = CompletionProvider()

        # Act
        items = provider._get_module_member_completions("pe.rich_signature", access_chain="")

        # Assert: pe.rich_signature has known sub-fields
        labels = {item.label for item in items}
        assert "offset" in labels
        assert "length" in labels
        assert "key" in labels
        # Must not return empty list - confirms lines 139-140 ran to completion
        assert len(items) > 0

    def test_dotted_module_name_with_access_chain_merges_chains(self) -> None:
        # Arrange: 'pe.rich_signature' with access_chain='version' causes the
        # merged chain 'rich_signature.version' to be passed to the helper,
        # which resolves to pe.rich_signature.version function completions.
        # This exercises line 141-142: chain = f"{chain}.{access_chain}".
        provider = CompletionProvider()

        # Act: access_chain is non-empty, triggering the f-string merge
        items = provider._get_module_member_completions("pe.rich_signature", access_chain="version")

        # Assert: the merged chain navigates into a valid pe sub-field tree
        # The result is the full pe member list resolved from that access path
        assert len(items) > 0

    def test_dotted_unknown_root_returns_empty(self) -> None:
        # Arrange: dotted name where root module does not exist
        provider = CompletionProvider()

        # Act
        items = provider._get_module_member_completions("unknown_xyz.field")

        # Assert: no module found -> empty list (exercises line 135-136 path)
        assert items == []

    def test_simple_module_name_without_dot_returns_members(self) -> None:
        # Arrange: no dot in module_name; the dotted-path branches are skipped.
        # This provides the baseline to contrast with the dotted-path tests.
        provider = CompletionProvider()

        # Act
        items = provider._get_module_member_completions("pe")

        # Assert: pe has many members
        labels = {item.label for item in items}
        assert "imphash" in labels
        assert len(items) > 5


# ---------------------------------------------------------------------------
# _get_workspace_rule_completions: early return when self.runtime is None
# (line 156-157)
# ---------------------------------------------------------------------------


class TestWorkspaceRuleCompletionsNoRuntime:
    """_get_workspace_rule_completions guards itself with an early return when
    self.runtime is falsy.  Although get_completions already guards the call
    site with 'if self.runtime and uri', the method remains callable directly
    and must be safe without a runtime.
    """

    def test_no_runtime_returns_empty_list(self) -> None:
        # Arrange: provider with no runtime
        provider = CompletionProvider(runtime=None)

        # Act: call the private method directly - exercises lines 156-157
        items = provider._get_workspace_rule_completions("file:///tmp/test.yar")

        # Assert: safe early return, no exception
        assert items == []

    def test_no_runtime_completions_list_is_plain_list(self) -> None:
        # The return type annotation is list[CompletionItem]; verify the type.
        provider = CompletionProvider(runtime=None)

        items = provider._get_workspace_rule_completions("file:///tmp/any.yar")

        assert isinstance(items, list)


# ---------------------------------------------------------------------------
# _get_workspace_rule_completions: exception handler (lines 176-177)
# ---------------------------------------------------------------------------


class _FaultyWorkspaceRuntime(LspRuntime):
    """LspRuntime subclass that raises during iter_workspace_documents to
    exercise the exception-swallowing branch at lines 176-177."""

    def iter_workspace_documents(self) -> list[Any]:
        raise RuntimeError("simulated workspace index failure")


class TestWorkspaceRuleCompletionsExceptionHandler:
    """The exception handler in _get_workspace_rule_completions must swallow
    any error from iter_workspace_documents and return whatever partial results
    were collected before the failure.
    """

    def test_exception_during_workspace_iteration_is_swallowed(self) -> None:
        # Arrange: runtime whose iter_workspace_documents raises.
        # Multi-line text is required: analyze_context only returns "condition"
        # when the cursor line is inside a condition section of a rule block.
        runtime = _FaultyWorkspaceRuntime()
        uri = "file:///tmp/fault_test.yar"
        # Line 0: 'rule r {'  Line 1: '  condition:'  Line 2: '    ' (cursor here)
        text = "rule r {\n  condition:\n    "
        runtime.open_document(uri, text)
        provider = CompletionProvider(runtime)

        # Act: position (line=2, char=4) is inside the condition body; with
        # runtime + uri present, get_completions calls _get_workspace_rule_completions
        # which calls iter_workspace_documents -> RuntimeError -> swallowed.
        result = provider.get_completions(text, _pos(2, 4), uri)

        # Assert: exception was swallowed; condition completions still returned
        assert result.is_incomplete is False
        labels = {item.label for item in result.items}
        assert len(labels) > 0

    def test_exception_during_workspace_iteration_logs_debug(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Arrange: multi-line text needed to reach condition context (see above)
        runtime = _FaultyWorkspaceRuntime()
        uri = "file:///tmp/fault_log_test.yar"
        text = "rule r {\n  condition:\n    "
        runtime.open_document(uri, text)
        provider = CompletionProvider(runtime)

        # Act: capture DEBUG log output from the completion module logger
        with caplog.at_level(logging.DEBUG, logger="yaraast.lsp.completion"):
            provider.get_completions(text, _pos(2, 4), uri)

        # Assert: the exception is logged at DEBUG level with exc_info.
        # Log call: logger.debug("Operation failed in %s", __name__, exc_info=True)
        # getMessage() interpolates to "Operation failed in yaraast.lsp.completion".
        completion_debug = [
            r
            for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "yaraast.lsp.completion"
        ]
        assert any("Operation failed" in r.getMessage() for r in completion_debug)

    def test_workspace_completions_with_exception_do_not_raise(self, tmp_path: Path) -> None:
        # Integration variant: even with a broken workspace iterator, get_completions
        # must complete successfully without raising.
        runtime = _FaultyWorkspaceRuntime()
        target = tmp_path / "target.yar"
        target.write_text("rule target_rule {\n  condition:\n    ", encoding="utf-8")
        uri = path_to_uri(target)
        text = target.read_text(encoding="utf-8")
        runtime.open_document(uri, text)

        provider = CompletionProvider(runtime)

        # Request completions at the start of the condition body (line 2, char 4)
        result = provider.get_completions(text, _pos(2, 4), uri)

        assert isinstance(result.items, list)


# ---------------------------------------------------------------------------
# Unreachability documentation tests
# ---------------------------------------------------------------------------


class TestStructurallyUnreachableBranches:
    """Document branches that coverage reports as missing but that cannot be
    reached through the public API without corrupting real Python objects.

    These tests exist to prove the structural guarantee that prevents those
    branches from being exercised, not to reach them artificially.
    """

    def test_get_rule_names_never_returns_empty_string(self) -> None:
        # Line 166->165: if rule_name and rule_name not in seen (False when not rule_name)
        # YARA rule names are non-empty identifiers by grammar; the real parser
        # never produces a symbol record with an empty name for rule symbols.
        from yaraast.lsp.document_context import DocumentContext

        cases = [
            "rule alpha { condition: true }",
            "rule beta { condition: false }",
            "rule alpha { condition: true }\nrule beta { condition: true }",
        ]
        for text in cases:
            dc = DocumentContext("file://test.yar", text)
            names = dc.get_rule_names()
            for name in names:
                assert name, f"Empty rule name produced from: {text!r}"
