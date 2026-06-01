"""Diagnostic-code handlers for semantic LSP quick fixes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeGuard, cast

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


def _is_arity_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def handle_module_not_imported(
    _provider: Any, _text: str, diagnostic: Diagnostic, uri: str, metadata: Mapping[str, object]
) -> list[CodeAction]:
    module_name = metadata.get("module")
    if isinstance(module_name, str):
        return create_import_module_action(module_name, diagnostic, uri)
    return []


def handle_module_function_not_found(
    provider: Any, text: str, diagnostic: Diagnostic, uri: str, metadata: Mapping[str, object]
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
    _provider: Any, text: str, diagnostic: Diagnostic, uri: str, metadata: Mapping[str, object]
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
        and _is_arity_int(expected_min)
        and expected_min >= 1
    ):
        return create_add_placeholder_argument_action(text, diagnostic, uri, function_name)
    if (
        isinstance(function_name, str)
        and arity_kind == "exact"
        and _is_arity_int(actual_args)
        and _is_arity_int(expected_args)
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
        and _is_arity_int(actual_args)
        and _is_arity_int(expected_max)
        and actual_args > expected_max
    ):
        return create_trim_arguments_action(text, diagnostic, uri, function_name, expected_max)
    if (
        isinstance(function_name, str)
        and arity_kind == "exact"
        and _is_arity_int(actual_args)
        and _is_arity_int(expected_args)
        and actual_args > expected_args
    ):
        return create_trim_arguments_action(text, diagnostic, uri, function_name, expected_args)
    return []


def handle_unknown_function(
    _provider: Any, text: str, diagnostic: Diagnostic, uri: str, metadata: Mapping[str, object]
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
    provider: Any, text: str, diagnostic: Diagnostic, uri: str, metadata: Mapping[str, object]
) -> list[CodeAction]:
    identifier = metadata.get("identifier")
    if isinstance(identifier, str):
        return cast(
            list[CodeAction],
            provider._create_rename_duplicate_action_from_identifier(
                text, diagnostic, uri, identifier
            ),
        )
    return []


def handle_validation_or_undefined(
    provider: Any, text: str, diagnostic: Diagnostic, uri: str, metadata: Mapping[str, object]
) -> list[CodeAction]:
    identifier = metadata.get("identifier")
    if isinstance(identifier, str) and identifier.startswith("$"):
        return cast(
            list[CodeAction],
            provider._create_add_string_action_from_identifier(text, diagnostic, uri, identifier),
        )
    module_name = metadata.get("module")
    if isinstance(module_name, str) and module_name in MODULE_DOCS:
        return create_import_module_action(module_name, diagnostic, uri)
    return []
