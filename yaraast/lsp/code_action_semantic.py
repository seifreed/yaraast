"""Semantic and heuristic quick fixes for LSP code actions."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any, cast

from lsprotocol.types import CodeAction, CodeActionKind, Diagnostic, WorkspaceEdit

from yaraast.lsp.code_action_semantic_handlers import (
    handle_duplicate_string_identifier,
    handle_invalid_arity,
    handle_module_function_not_found,
    handle_module_not_imported,
    handle_unknown_function,
    handle_validation_or_undefined,
)
from yaraast.lsp.code_action_semantic_quickfixes import (
    create_import_module_action,
    create_rename_duplicate_action,
)


class SemanticCodeActionMixin:
    """Helpers for diagnostic-driven quick fixes."""

    def _create_semantic_actions(
        self: Any,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        data = self._get_diagnostic_data(diagnostic)
        if data is None:
            return []

        code = data.get("code")
        metadata = data.get("metadata")
        if not isinstance(code, str) or not isinstance(metadata, Mapping):
            return []

        handlers = {
            "semantic.module_not_imported": handle_module_not_imported,
            "compiler.module_not_imported": handle_module_not_imported,
            "semantic.module_function_not_found": handle_module_function_not_found,
            "semantic.invalid_arity": handle_invalid_arity,
            "semantic.unknown_function": handle_unknown_function,
            "semantic.duplicate_string_identifier": handle_duplicate_string_identifier,
            "semantic.undefined_string_identifier": handle_validation_or_undefined,
            "semantic.validation_error": handle_validation_or_undefined,
            "compiler.undefined_identifier": handle_validation_or_undefined,
        }
        handler = handlers.get(code)
        if handler is not None:
            return handler(self, text, diagnostic, uri, metadata)

        return []

    def _create_add_string_actions(
        self: Any,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to add missing string definition."""
        match = re.search(r"\$\w+", diagnostic.message)
        if not match:
            return []
        return cast(
            list[CodeAction],
            self._create_add_string_action_from_identifier(text, diagnostic, uri, match.group(0)),
        )

    def _create_add_string_action_from_identifier(
        self: Any,
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
        self: Any,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to import missing module."""
        match = re.search(r"Module '(\w+)' not imported", diagnostic.message)
        if match is None:
            match = re.search(r"not imported:\s*(\w+)", diagnostic.message, re.IGNORECASE)
        if match is None:
            match = re.search(r"Module\s+(\w+)\s+not imported", diagnostic.message)
        if not match:
            return []
        return cast(
            list[CodeAction],
            self._create_import_module_action_from_name(match.group(1), diagnostic, uri),
        )

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
