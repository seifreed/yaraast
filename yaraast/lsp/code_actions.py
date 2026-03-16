"""Code actions provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import CodeAction, Diagnostic, Range

from yaraast.lsp.authoring import AuthoringActions
from yaraast.lsp.code_action_refactors import RefactorCodeActionMixin
from yaraast.lsp.code_action_semantic import SemanticCodeActionMixin
from yaraast.lsp.code_action_structured import StructuredCodeActionMixin


class CodeActionsProvider(
    StructuredCodeActionMixin,
    SemanticCodeActionMixin,
    RefactorCodeActionMixin,
):
    """Provides code actions (quick fixes)."""

    def __init__(self) -> None:
        self.authoring = AuthoringActions()

    def get_code_actions(
        self,
        text: str,
        range_: Range,
        diagnostics: list[Diagnostic],
        uri: str,
    ) -> list[CodeAction]:
        """
        Get code actions for the given range and diagnostics.

        Args:
            text: The YARA source code
            range_: The range to get actions for
            diagnostics: Diagnostics in the range
            uri: The document URI

        Returns:
            List of available code actions
        """
        actions = []

        # Add quick fixes for diagnostics
        for diagnostic in diagnostics:
            structured_actions = self._create_structured_actions(diagnostic, uri)
            actions.extend(structured_actions)
            if structured_actions:
                continue

            semantic_actions = self._create_semantic_actions(text, diagnostic, uri)
            actions.extend(semantic_actions)
            if semantic_actions:
                continue

            if "undefined variable" in diagnostic.message.lower():
                # Suggest adding string definition
                actions.extend(self._create_add_string_actions(text, diagnostic, uri))

            if "not imported" in diagnostic.message.lower():
                # Suggest importing module
                actions.extend(self._create_import_module_actions(text, diagnostic, uri))

            if "duplicate string identifier" in diagnostic.message.lower():
                # Suggest renaming duplicate
                actions.extend(self._create_rename_duplicate_actions(text, diagnostic, uri))

        # Add refactoring actions
        actions.extend(self._get_refactoring_actions(text, range_, uri))

        return actions
