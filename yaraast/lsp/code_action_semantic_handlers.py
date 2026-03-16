"""Diagnostic-code handlers for semantic LSP quick fixes."""

from __future__ import annotations

from lsprotocol.types import CodeAction, Diagnostic

from yaraast.lsp.code_action_semantic_quickfixes import (
    create_add_missing_arguments_action,
    create_add_placeholder_argument_action,
    create_import_module_action,
    create_replace_builtin_function_actions,
    create_replace_module_function_actions,
    create_trim_arguments_action,
)
from yaraast.lsp.lsp_docs import MODULE_DOCS


def handle_module_not_imported(
    _provider, _text: str, diagnostic: Diagnostic, uri: str, metadata
) -> list[CodeAction]:
    module_name = metadata.get("module")
    if isinstance(module_name, str):
        return create_import_module_action(module_name, diagnostic, uri)
    return []


def handle_module_function_not_found(
    provider, text: str, diagnostic: Diagnostic, uri: str, metadata
) -> list[CodeAction]:
    module_name = metadata.get("module")
    function_name = metadata.get("function")
    available = metadata.get("available_functions")
    if (
        isinstance(module_name, str)
        and isinstance(function_name, str)
        and isinstance(available, list)
    ):
        return create_replace_module_function_actions(
            text,
            diagnostic,
            uri,
            module_name,
            function_name,
            [item for item in available if isinstance(item, str)],
        )
    return []


def handle_invalid_arity(
    _provider, text: str, diagnostic: Diagnostic, uri: str, metadata
) -> list[CodeAction]:
    function_name = metadata.get("function")
    arity_kind = metadata.get("arity_kind")
    actual_args = metadata.get("actual_args")
    expected_min = metadata.get("expected_min")
    expected_args = metadata.get("expected_args")
    expected_max = metadata.get("expected_max")
    if (
        isinstance(function_name, str)
        and arity_kind == "min"
        and actual_args == 0
        and isinstance(expected_min, int)
        and expected_min >= 1
    ):
        return create_add_placeholder_argument_action(text, diagnostic, uri, function_name)
    if (
        isinstance(function_name, str)
        and arity_kind == "exact"
        and isinstance(actual_args, int)
        and isinstance(expected_args, int)
        and actual_args < expected_args
    ):
        return create_add_missing_arguments_action(
            text,
            diagnostic,
            uri,
            function_name,
            expected_args - actual_args,
        )
    if (
        isinstance(function_name, str)
        and arity_kind == "max"
        and isinstance(actual_args, int)
        and isinstance(expected_max, int)
        and actual_args > expected_max
    ):
        return create_trim_arguments_action(text, diagnostic, uri, function_name, expected_max)
    if (
        isinstance(function_name, str)
        and arity_kind == "exact"
        and isinstance(actual_args, int)
        and isinstance(expected_args, int)
        and actual_args > expected_args
    ):
        return create_trim_arguments_action(text, diagnostic, uri, function_name, expected_args)
    return []


def handle_unknown_function(
    _provider, text: str, diagnostic: Diagnostic, uri: str, metadata
) -> list[CodeAction]:
    function_name = metadata.get("function")
    suggested = metadata.get("suggested_functions")
    if isinstance(function_name, str) and isinstance(suggested, list):
        return create_replace_builtin_function_actions(
            text,
            diagnostic,
            uri,
            function_name,
            [item for item in suggested if isinstance(item, str)],
        )
    return []


def handle_duplicate_string_identifier(
    provider, text: str, diagnostic: Diagnostic, uri: str, metadata
) -> list[CodeAction]:
    identifier = metadata.get("identifier")
    if isinstance(identifier, str):
        return provider._create_rename_duplicate_action_from_identifier(
            text, diagnostic, uri, identifier
        )
    return []


def handle_validation_or_undefined(
    provider, text: str, diagnostic: Diagnostic, uri: str, metadata
) -> list[CodeAction]:
    identifier = metadata.get("identifier")
    if isinstance(identifier, str) and identifier.startswith("$"):
        return provider._create_add_string_action_from_identifier(text, diagnostic, uri, identifier)
    module_name = metadata.get("module")
    if isinstance(module_name, str) and module_name in MODULE_DOCS:
        return create_import_module_action(module_name, diagnostic, uri)
    return []
