"""Structured semantic-action dispatch for LSP quick fixes."""

from __future__ import annotations

from collections.abc import Mapping

from lsprotocol.types import CodeAction, Diagnostic

from yaraast.lsp.code_action_semantic_handlers import (
    handle_duplicate_string_identifier,
    handle_invalid_arity,
    handle_module_function_not_found,
    handle_module_not_imported,
    handle_unknown_function,
    handle_validation_or_undefined,
)


def create_semantic_actions(
    provider, text: str, diagnostic: Diagnostic, uri: str
) -> list[CodeAction]:
    """Create semantic quick fixes from structured diagnostic data."""
    data = provider._get_diagnostic_data(diagnostic)
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
        return handler(provider, text, diagnostic, uri, metadata)

    return []
