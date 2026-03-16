"""Semantic and heuristic quick fixes for LSP code actions."""

from __future__ import annotations

import re

from lsprotocol.types import CodeAction, CodeActionKind, Diagnostic, WorkspaceEdit

from yaraast.lsp.code_action_semantic_dispatch import create_semantic_actions
from yaraast.lsp.code_action_semantic_quickfixes import (
    create_add_missing_arguments_action,
    create_add_placeholder_argument_action,
    create_import_module_action,
    create_rename_duplicate_action,
    create_replace_builtin_function_actions,
    create_replace_module_function_actions,
    create_trim_arguments_action,
)


class SemanticCodeActionMixin:
    """Helpers for diagnostic-driven quick fixes."""

    def _create_semantic_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        return create_semantic_actions(self, text, diagnostic, uri)

    def _create_replace_module_function_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
        module_name: str,
        function_name: str,
        available_functions: list[str],
    ) -> list[CodeAction]:
        return create_replace_module_function_actions(
            text, diagnostic, uri, module_name, function_name, available_functions
        )

    def _create_replace_builtin_function_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
        function_name: str,
        suggested_functions: list[str],
    ) -> list[CodeAction]:
        return create_replace_builtin_function_actions(
            text, diagnostic, uri, function_name, suggested_functions
        )

    def _create_add_placeholder_argument_action(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
        function_name: str,
    ) -> list[CodeAction]:
        return create_add_placeholder_argument_action(text, diagnostic, uri, function_name)

    def _create_add_missing_arguments_action(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
        function_name: str,
        missing_count: int,
    ) -> list[CodeAction]:
        return create_add_missing_arguments_action(
            text, diagnostic, uri, function_name, missing_count
        )

    def _create_trim_arguments_action(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
        function_name: str,
        keep_args: int,
    ) -> list[CodeAction]:
        return create_trim_arguments_action(text, diagnostic, uri, function_name, keep_args)

    def _create_add_string_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to add missing string definition."""
        match = re.search(r"\$\w+", diagnostic.message)
        if not match:
            return []
        return self._create_add_string_action_from_identifier(text, diagnostic, uri, match.group(0))

    def _create_add_string_action_from_identifier(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
        string_id: str,
    ) -> list[CodeAction]:
        """Create actions to add a missing string definition from a known identifier."""
        structural = self.authoring.create_missing_string(text, string_id, diagnostic.range)
        if structural is None:
            return []
        return [
            CodeAction(
                title=structural.title,
                kind=CodeActionKind.QuickFix,
                edit=WorkspaceEdit(changes={uri: [structural.edit]}),
                diagnostics=[diagnostic],
            )
        ]

    def _create_import_module_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to import missing module."""
        match = re.search(r"Module '(\w+)' not imported", diagnostic.message)
        if not match:
            return []
        return self._create_import_module_action_from_name(match.group(1), diagnostic, uri)

    def _create_import_module_action_from_name(
        self,
        module_name: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create an import-module quick fix from a structured module name."""
        return create_import_module_action(module_name, diagnostic, uri)

    def _create_rename_duplicate_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to rename duplicate string identifier."""
        match = re.search(r"'\$(\w+)'", diagnostic.message)
        if not match:
            return []

        return self._create_rename_duplicate_action_from_identifier(
            text,
            diagnostic,
            uri,
            f"${match.group(1)}",
        )

    def _create_rename_duplicate_action_from_identifier(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
        identifier: str,
    ) -> list[CodeAction]:
        """Create a duplicate-string rename quick fix from a known identifier."""
        return create_rename_duplicate_action(text, diagnostic, uri, identifier)
