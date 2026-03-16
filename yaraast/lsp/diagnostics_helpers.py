"""Helper functions for LSP diagnostic conversion and metadata extraction."""

from __future__ import annotations

import difflib
import re

from lsprotocol.types import (
    Diagnostic,
    DiagnosticRelatedInformation,
    DiagnosticSeverity,
    Location,
    Position,
    Range,
)

from yaraast.lsp.lsp_docs import BUILTIN_DOCS, MODULE_DOCS
from yaraast.lsp.utf16 import utf8_col_to_utf16


def parser_error_to_diagnostic(error, diagnostic_data_cls) -> Diagnostic:
    line = error.line - 1 if error.line > 0 else 0
    col = error.column - 1 if error.column > 0 else 0
    # Convert column to UTF-16 code units for LSP compliance
    source_line = ""
    source = getattr(error, "source", None) or getattr(error, "text", None) or ""
    if source:
        lines = source.split("\n")
        if 0 <= line < len(lines):
            source_line = lines[line]
    if source_line:
        col = utf8_col_to_utf16(source_line, col)
    return Diagnostic(
        range=Range(
            start=Position(line=line, character=col),
            end=Position(line=line, character=col + 10),
        ),
        message=str(error),
        severity=DiagnosticSeverity.Error,
        code="parser.syntax_error",
        source="yaraast-parser",
        data=diagnostic_data_cls(
            code="parser.syntax_error",
            severity="error",
            error_type="parser",
            metadata={"line": line, "column": col},
        ).to_dict(),
    )


def compiler_error_to_diagnostic(message: str, diagnostic_data_cls) -> Diagnostic:
    code = "compiler.compilation_error"
    metadata: dict[str, object] = {"backend": "libyara", "message": message}
    syntax_error = re.search(r"syntax error", message, re.IGNORECASE)
    undefined_identifier = re.search(
        r"undefined identifier[: ]+['\"]?([^'\"\n]+)['\"]?",
        message,
        re.IGNORECASE,
    )
    include_error = re.search(r"include.*?['\"]([^'\"]+)['\"]", message, re.IGNORECASE)
    if syntax_error:
        code = "compiler.syntax_error"
    if undefined_identifier:
        identifier = undefined_identifier.group(1).strip()
        metadata["identifier"] = identifier
        module_name = identifier.split(".", 1)[0]
        if identifier in MODULE_DOCS:
            code = "compiler.module_not_imported"
            metadata["module"] = identifier
        elif module_name in MODULE_DOCS:
            code = "compiler.module_not_imported"
            metadata["module"] = module_name
            metadata["member"] = identifier.split(".", 1)[1]
        else:
            code = "compiler.undefined_identifier"
    if include_error:
        code = "compiler.include_error"
        metadata["include"] = include_error.group(1)

    return Diagnostic(
        range=Range(start=Position(line=0, character=0), end=Position(line=0, character=1)),
        message=message,
        severity=DiagnosticSeverity.Error,
        code=code,
        source="yaraast-compiler",
        data=diagnostic_data_cls(
            code=code,
            severity="error",
            error_type="compiler",
            metadata=metadata,
        ).to_dict(),
    )


def error_code(error) -> str:
    message = error.message.lower()
    if "undefined variable" in message:
        return (
            "semantic.undefined_string_identifier"
            if "$" in error.message
            else "semantic.undefined_identifier"
        )
    if "duplicate string identifier" in message:
        return "semantic.duplicate_string_identifier"
    if "not imported" in message:
        return "semantic.module_not_imported"
    if "function '" in message and "not found in module" in message:
        return "semantic.module_function_not_found"
    if "expects" in message and "argument" in message:
        return "semantic.invalid_arity"
    if "unknown function" in message:
        return "semantic.unknown_function"
    if "include" in message and "error" in message:
        return "compiler.include_error"
    return "semantic.validation_error"


def related_info(error, diagnostic_range: Range) -> list[DiagnosticRelatedInformation] | None:
    if not error.location or not error.location.file:
        return None
    return [
        DiagnosticRelatedInformation(
            location=Location(uri=error.location.file, range=diagnostic_range),
            message=error.message,
        )
    ]


def patches_for_error(error, diagnostic_range: Range, diagnostic_patch_cls) -> list[object]:
    message = error.message
    if "Duplicate string identifier" in message:
        match = re.search(r"'\$(\w+)'", message)
        if match:
            identifier = match.group(1)
            return [diagnostic_patch_cls(diagnostic_range, f"${identifier}_2")]
    if "Module '" in message and "not imported" in message:
        match = re.search(r"Module '(\w+)' not imported", message)
        if match:
            module_name = match.group(1)
            return [
                diagnostic_patch_cls(
                    Range(start=Position(line=0, character=0), end=Position(line=0, character=0)),
                    f'import "{module_name}"\n',
                )
            ]
    return []


def metadata_for_error(error) -> dict[str, object]:
    message = error.message
    metadata: dict[str, object] = {}

    undefined_identifier = re.search(r"(?i)undefined variable (\$?\w+)", message)
    if undefined_identifier:
        identifier = undefined_identifier.group(1)
        metadata["identifier"] = identifier
        if not identifier.startswith("$") and identifier in MODULE_DOCS:
            metadata["module"] = identifier

    duplicate = re.search(r"'\$(\w+)'", message)
    if duplicate:
        metadata["identifier"] = f"${duplicate.group(1)}"

    missing_module = re.search(r"Module '(\w+)' not imported", message)
    if missing_module:
        metadata["module"] = missing_module.group(1)

    module_function = re.search(r"Function '(\w+)' not found in module '(\w+)'", message)
    if module_function:
        metadata["function"] = module_function.group(1)
        metadata["module"] = module_function.group(2)
        if error.suggestion and error.suggestion.startswith("Available functions: "):
            available = error.suggestion.removeprefix("Available functions: ").strip()
            if available:
                metadata["available_functions"] = [
                    item.strip() for item in available.split(",") if item.strip()
                ]

    unknown_function = re.search(r"Unknown function '(\w+)'", message)
    if unknown_function:
        metadata["function"] = unknown_function.group(1)
        suggestions = suggest_builtin_functions(metadata["function"])
        if suggestions:
            metadata["suggested_functions"] = suggestions

    invalid_arity = re.search(r"Function '(\w+)' expects .* got (\d+)", message)
    if invalid_arity:
        metadata["function"] = invalid_arity.group(1)
        metadata["actual_args"] = int(invalid_arity.group(2))

        at_least = re.search(r"expects at least (\d+) argument", message)
        if at_least:
            metadata["arity_kind"] = "min"
            metadata["expected_min"] = int(at_least.group(1))

        at_most = re.search(r"expects at most (\d+) argument", message)
        if at_most:
            metadata["arity_kind"] = "max"
            metadata["expected_max"] = int(at_most.group(1))

        exact = re.search(r"expects (\d+) argument\(s\)", message)
        if exact:
            metadata["arity_kind"] = "exact"
            metadata["expected_args"] = int(exact.group(1))

    include_error = re.search(r"include.*?['\"]([^'\"]+)['\"]", message, re.IGNORECASE)
    if include_error:
        metadata["include"] = include_error.group(1)

    return metadata


def suggest_builtin_functions(function_name: str) -> list[str]:
    builtins = sorted(BUILTIN_DOCS.keys())
    return difflib.get_close_matches(function_name, builtins, n=3, cutoff=0.5)
