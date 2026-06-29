# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for yaraast/lsp/lsp_types.py.

Purpose
-------
Drive lsp_types coverage toward 100% by exercising:
  1. Normal import path — module exports every name in __all__.
  2. _is_missing_lsprotocol_types helper — all four decision branches.
  3. Fallback import path (lines 93-104) — triggered by temporarily removing
     the site-packages directory from sys.path so the primary try-block raises
     ImportError(name='lsprotocol'), then verifying the module self-heals and
     re-exports all expected symbols.

Genuinely unreachable line
--------------------------
Line 91 true-branch (``if not _is_missing_lsprotocol_types(exc): raise``):
  The containing try-block is a single ``from lsprotocol.types import (...)``
  statement. Any ImportError it raises will carry exc.name == 'lsprotocol' or
  'lsprotocol.types', both of which are IN the sentinel set, so the guard
  evaluates to False and the re-raise never fires. No real execution path can
  set exc.name to an unrelated value inside that try-block; the branch is
  structurally dead code without source modification.
"""

from __future__ import annotations

import importlib
import site
import sys
from types import ModuleType

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _remove_lsprotocol_from_modules() -> dict[str, ModuleType]:
    """Pop every lsprotocol-related entry from sys.modules.

    Returns the mapping so callers can restore it during cleanup.
    """
    removed: dict[str, ModuleType] = {}
    for key in list(sys.modules.keys()):
        if "lsprotocol" in key:
            removed[key] = sys.modules.pop(key)
    return removed


def _restore_modules(saved: dict[str, ModuleType]) -> None:
    sys.modules.update(saved)


# ---------------------------------------------------------------------------
# Section 1 — _is_missing_lsprotocol_types
# ---------------------------------------------------------------------------


class TestIsMissingLsprotocolTypes:
    """Validate the ImportError classifier used by the fallback guard."""

    def test_returns_true_for_lsprotocol_name(self) -> None:
        """ImportError whose name is 'lsprotocol' must return True."""
        from yaraast.lsp.lsp_types import _is_missing_lsprotocol_types

        exc = ImportError("No module named 'lsprotocol'")
        exc.name = "lsprotocol"
        assert _is_missing_lsprotocol_types(exc) is True

    def test_returns_true_for_lsprotocol_types_name(self) -> None:
        """ImportError whose name is 'lsprotocol.types' must return True."""
        from yaraast.lsp.lsp_types import _is_missing_lsprotocol_types

        exc = ImportError("No module named 'lsprotocol.types'")
        exc.name = "lsprotocol.types"
        assert _is_missing_lsprotocol_types(exc) is True

    def test_returns_false_for_unrelated_module_name(self) -> None:
        """ImportError from an unrelated module must return False."""
        from yaraast.lsp.lsp_types import _is_missing_lsprotocol_types

        exc = ImportError("No module named 'pygls'")
        exc.name = "pygls"
        assert _is_missing_lsprotocol_types(exc) is False

    def test_returns_false_when_name_is_none(self) -> None:
        """ImportError with name=None must return False (empty string fallback)."""
        from yaraast.lsp.lsp_types import _is_missing_lsprotocol_types

        exc = ImportError("synthetic error")
        exc.name = None
        assert _is_missing_lsprotocol_types(exc) is False


# ---------------------------------------------------------------------------
# Section 2 — Normal-path symbol exports
# ---------------------------------------------------------------------------


class TestNormalPathExports:
    """Verify every name in __all__ is accessible after a normal import."""

    def test_yaraast_runtime_status_constant(self) -> None:
        """YARAAST_RUNTIME_STATUS must equal the protocol method string."""
        from yaraast.lsp.lsp_types import YARAAST_RUNTIME_STATUS

        assert YARAAST_RUNTIME_STATUS == "yaraast/status"

    def test_text_document_method_constants_are_strings(self) -> None:
        """TEXT_DOCUMENT_* constants must be non-empty strings."""
        from yaraast.lsp.lsp_types import (
            TEXT_DOCUMENT_CODE_ACTION,
            TEXT_DOCUMENT_COMPLETION,
            TEXT_DOCUMENT_DEFINITION,
            TEXT_DOCUMENT_DIAGNOSTIC,
            TEXT_DOCUMENT_DID_CHANGE,
            TEXT_DOCUMENT_DID_CLOSE,
            TEXT_DOCUMENT_DID_OPEN,
            TEXT_DOCUMENT_DID_SAVE,
            TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT,
            TEXT_DOCUMENT_DOCUMENT_LINK,
            TEXT_DOCUMENT_DOCUMENT_SYMBOL,
            TEXT_DOCUMENT_FOLDING_RANGE,
            TEXT_DOCUMENT_FORMATTING,
            TEXT_DOCUMENT_HOVER,
            TEXT_DOCUMENT_PREPARE_RENAME,
            TEXT_DOCUMENT_RANGE_FORMATTING,
            TEXT_DOCUMENT_REFERENCES,
            TEXT_DOCUMENT_RENAME,
            TEXT_DOCUMENT_SELECTION_RANGE,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE,
            TEXT_DOCUMENT_SIGNATURE_HELP,
        )

        constants = [
            TEXT_DOCUMENT_CODE_ACTION,
            TEXT_DOCUMENT_COMPLETION,
            TEXT_DOCUMENT_DEFINITION,
            TEXT_DOCUMENT_DIAGNOSTIC,
            TEXT_DOCUMENT_DID_CHANGE,
            TEXT_DOCUMENT_DID_CLOSE,
            TEXT_DOCUMENT_DID_OPEN,
            TEXT_DOCUMENT_DID_SAVE,
            TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT,
            TEXT_DOCUMENT_DOCUMENT_LINK,
            TEXT_DOCUMENT_DOCUMENT_SYMBOL,
            TEXT_DOCUMENT_FOLDING_RANGE,
            TEXT_DOCUMENT_FORMATTING,
            TEXT_DOCUMENT_HOVER,
            TEXT_DOCUMENT_PREPARE_RENAME,
            TEXT_DOCUMENT_RANGE_FORMATTING,
            TEXT_DOCUMENT_REFERENCES,
            TEXT_DOCUMENT_RENAME,
            TEXT_DOCUMENT_SELECTION_RANGE,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE,
            TEXT_DOCUMENT_SIGNATURE_HELP,
        ]
        for constant in constants:
            message = f"Expected non-empty string, got {constant!r}"
            assert isinstance(constant, str) and constant, message

    def test_workspace_constants_are_strings(self) -> None:
        """WORKSPACE_* constants must be non-empty strings."""
        from yaraast.lsp.lsp_types import (
            WORKSPACE_DID_CHANGE_CONFIGURATION,
            WORKSPACE_DID_CHANGE_WATCHED_FILES,
            WORKSPACE_SYMBOL,
        )

        assert isinstance(WORKSPACE_DID_CHANGE_CONFIGURATION, str)
        assert isinstance(WORKSPACE_DID_CHANGE_WATCHED_FILES, str)
        assert isinstance(WORKSPACE_SYMBOL, str)

    def test_lsprotocol_types_are_classes(self) -> None:
        """All re-exported lsprotocol classes must be importable as real types."""
        from yaraast.lsp.lsp_types import (
            CodeAction,
            CodeActionOptions,
            CodeActionParams,
            CompletionList,
            CompletionOptions,
            CompletionParams,
            DefinitionParams,
            DiagnosticOptions,
            DidChangeConfigurationParams,
            DidChangeTextDocumentParams,
            DidChangeWatchedFilesParams,
            DidCloseTextDocumentParams,
            DidOpenTextDocumentParams,
            DidSaveTextDocumentParams,
            DocumentDiagnosticParams,
            DocumentDiagnosticReportKind,
            DocumentFormattingParams,
            DocumentHighlight,
            DocumentHighlightParams,
            DocumentLink,
            DocumentLinkParams,
            DocumentRangeFormattingParams,
            DocumentSymbol,
            DocumentSymbolParams,
            FoldingRange,
            FoldingRangeParams,
            FullDocumentDiagnosticReport,
            Hover,
            HoverParams,
            InitializeParams,
            Location,
            PrepareRenameParams,
            Range,
            ReferenceParams,
            RelatedFullDocumentDiagnosticReport,
            RenameParams,
            SelectionRange,
            SelectionRangeParams,
            SemanticTokens,
            SemanticTokensParams,
            SemanticTokensRangeParams,
            SemanticTokensRegistrationOptions,
            SignatureHelp,
            SignatureHelpOptions,
            SignatureHelpParams,
            SymbolInformation,
            TextEdit,
            WorkspaceEdit,
            WorkspaceFoldersServerCapabilities,
            WorkspaceSymbolParams,
        )

        exported_types = [
            CodeAction,
            CodeActionOptions,
            CodeActionParams,
            CompletionList,
            CompletionOptions,
            CompletionParams,
            DefinitionParams,
            DiagnosticOptions,
            DidChangeConfigurationParams,
            DidChangeTextDocumentParams,
            DidChangeWatchedFilesParams,
            DidCloseTextDocumentParams,
            DidOpenTextDocumentParams,
            DidSaveTextDocumentParams,
            DocumentDiagnosticParams,
            DocumentDiagnosticReportKind,
            DocumentFormattingParams,
            DocumentHighlight,
            DocumentHighlightParams,
            DocumentLink,
            DocumentLinkParams,
            DocumentRangeFormattingParams,
            DocumentSymbol,
            DocumentSymbolParams,
            FoldingRange,
            FoldingRangeParams,
            FullDocumentDiagnosticReport,
            Hover,
            HoverParams,
            InitializeParams,
            Location,
            PrepareRenameParams,
            Range,
            ReferenceParams,
            RelatedFullDocumentDiagnosticReport,
            RenameParams,
            SelectionRange,
            SelectionRangeParams,
            SemanticTokens,
            SemanticTokensParams,
            SemanticTokensRangeParams,
            SemanticTokensRegistrationOptions,
            SignatureHelp,
            SignatureHelpOptions,
            SignatureHelpParams,
            SymbolInformation,
            TextEdit,
            WorkspaceEdit,
            WorkspaceFoldersServerCapabilities,
            WorkspaceSymbolParams,
        ]
        for t in exported_types:
            assert isinstance(t, type) or callable(t), f"{t!r} is not a type or callable"

    def test_all_list_completeness(self) -> None:
        """Every name in __all__ must be resolvable as a real attribute."""
        import yaraast.lsp.lsp_types as lsp_types_mod

        for name in lsp_types_mod.__all__:
            assert hasattr(lsp_types_mod, name), f"__all__ member {name!r} not found on module"

    def test_did_open_method_string_value(self) -> None:
        """TEXT_DOCUMENT_DID_OPEN must carry the canonical LSP method name."""
        from yaraast.lsp.lsp_types import TEXT_DOCUMENT_DID_OPEN

        assert TEXT_DOCUMENT_DID_OPEN == "textDocument/didOpen"

    def test_hover_method_string_value(self) -> None:
        """TEXT_DOCUMENT_HOVER must carry the canonical LSP method name."""
        from yaraast.lsp.lsp_types import TEXT_DOCUMENT_HOVER

        assert TEXT_DOCUMENT_HOVER == "textDocument/hover"


# ---------------------------------------------------------------------------
# Section 3 — Fallback import path (lines 93-104)
# ---------------------------------------------------------------------------


class TestFallbackImportPath:
    """Exercise the except ImportError recovery block executed when the initial
    lsprotocol import fails because site-packages is absent from sys.path.

    The test temporarily removes the venv site-packages directory from sys.path
    and evicts all lsprotocol and yaraast.lsp.lsp_types entries from
    sys.modules, forcing the module to be re-imported from scratch.  Because
    the fallback block re-adds site-packages to sys.path and retries the
    import, the module must load successfully and export all expected symbols.
    """

    @staticmethod
    def _trigger_fallback() -> ModuleType:
        """Remove site-packages from sys.path, evict cached modules, re-import.

        Returns the freshly-imported module object, which exercised the fallback
        block (lines 93-104).  Restores sys.path and sys.modules to their
        pre-call state before returning so subsequent tests are not affected.
        """
        site_packages = site.getsitepackages()
        lsprotocol_sp: str | None = None
        for sp in site_packages:
            if sp in sys.path:
                lsprotocol_sp = sp
                break

        if lsprotocol_sp is None:
            pytest.skip("Cannot locate site-packages in sys.path — cannot trigger fallback")

        # Save everything before mutation, including the parent package reference.
        saved_lsprotocol = _remove_lsprotocol_from_modules()
        saved_lsp_types = sys.modules.pop("yaraast.lsp.lsp_types", None)

        # Python sets the submodule attribute on the parent package when a
        # submodule is imported. Capture the current attribute so we can restore
        # it exactly after the test — Python 3.13's importlib.reload() uses
        # object identity (is) to validate that the module matches sys.modules.
        lsp_parent = sys.modules.get("yaraast.lsp")
        parent_attr_before = getattr(lsp_parent, "lsp_types", None) if lsp_parent else None

        sys.path.remove(lsprotocol_sp)
        recovered: ModuleType
        try:
            recovered = importlib.import_module("yaraast.lsp.lsp_types")
        finally:
            # Remove the freshly-imported module from sys.modules so the
            # original cached object (restored below) is the authoritative copy.
            # This prevents importlib.reload() in other tests from receiving a
            # module object that does not match sys.modules[name] by identity.
            sys.modules.pop("yaraast.lsp.lsp_types", None)

            # Restore sys.path so lsprotocol is findable again.
            if lsprotocol_sp not in sys.path:
                sys.path.insert(0, lsprotocol_sp)

            # Restore lsprotocol sub-modules.
            _restore_modules(saved_lsprotocol)

            # Restore the original lsp_types module object as the canonical entry.
            if saved_lsp_types is not None:
                sys.modules["yaraast.lsp.lsp_types"] = saved_lsp_types

            # Restore the parent package's submodule attribute to the original
            # object. Without this, ``import yaraast.lsp.lsp_types`` from
            # another test returns the intermediate object (set by our import),
            # which then mismatches the restored sys.modules entry.
            # Python 3.13 importlib.reload() validates identity:
            #   sys.modules.get(name) is module
            # Use __dict__ directly to avoid both the mypy attr-defined error
            # (ModuleType has no declared lsp_types attr) and ruff B009/B010
            # (constant-string getattr/setattr).
            if lsp_parent is not None:
                if parent_attr_before is not None:
                    lsp_parent.__dict__["lsp_types"] = parent_attr_before
                else:
                    lsp_parent.__dict__.pop("lsp_types", None)

        return recovered

    def test_fallback_path_loads_module_when_site_packages_absent(self) -> None:
        """Module must self-heal via the fallback block and export all symbols."""
        recovered = self._trigger_fallback()

        # Assert: the recovered module must expose the runtime status constant.
        assert hasattr(recovered, "YARAAST_RUNTIME_STATUS")
        assert recovered.YARAAST_RUNTIME_STATUS == "yaraast/status"

    def test_fallback_path_exports_range_type(self) -> None:
        """Range must be a real class after the fallback import succeeds."""
        recovered = self._trigger_fallback()

        range_cls = recovered.Range
        assert isinstance(range_cls, type)
        assert range_cls.__module__ == "lsprotocol.types"

    def test_fallback_path_exports_all_all_members(self) -> None:
        """All __all__ members must be present after the fallback import path."""
        # Capture the expected __all__ from the already-imported stable module
        # before calling _trigger_fallback, which temporarily mutates sys.modules.
        import yaraast.lsp.lsp_types as stable_mod

        expected_all = list(stable_mod.__all__)

        recovered = self._trigger_fallback()

        for name in expected_all:
            assert hasattr(recovered, name), f"Fallback import missing __all__ member: {name!r}"

    def test_sentinel_set_constant(self) -> None:
        """_LSPROTOCOL_TYPES_IMPORT_NAMES must contain the two expected strings."""
        import yaraast.lsp.lsp_types as lsp_types_mod

        assert {"lsprotocol", "lsprotocol.types"} == lsp_types_mod._LSPROTOCOL_TYPES_IMPORT_NAMES
