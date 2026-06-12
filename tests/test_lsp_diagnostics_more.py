"""Real tests for LSP diagnostics (no mocks)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from lsprotocol.types import Diagnostic, DiagnosticSeverity
import pytest

from yaraast.ast.base import Location
from yaraast.lsp.diagnostics import DiagnosticData, DiagnosticsProvider
from yaraast.lsp.diagnostics_helpers import parser_error_to_diagnostic
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.utf16 import utf8_col_to_utf16
from yaraast.types.semantic_validator_core import ValidationError


def _diagnostic_data(diagnostic: Diagnostic) -> dict[str, Any]:
    data = diagnostic.data
    assert isinstance(data, dict)
    return data


def _diagnostic_metadata(diagnostic: Diagnostic) -> dict[str, Any]:
    metadata = _diagnostic_data(diagnostic)["metadata"]
    assert isinstance(metadata, dict)
    return metadata


def _diagnostic_patches(diagnostic: Diagnostic) -> list[dict[str, Any]]:
    patches = _diagnostic_data(diagnostic)["patches"]
    assert isinstance(patches, list)
    return patches


def test_diagnostics_rejects_invalid_uri() -> None:
    provider = DiagnosticsProvider()

    with pytest.raises(TypeError, match="Diagnostics URI must be a string or None"):
        provider.get_diagnostics("rule sample { condition: true }", cast(str, object()))


def test_diagnostics_parser_error() -> None:
    provider = DiagnosticsProvider()
    text = "rule bad { condition: "

    diags = provider.get_diagnostics(text)
    assert diags
    assert diags[0].source in {"yaraast-parser", "yaraast"}
    assert diags[0].code == "parser.syntax_error"
    assert _diagnostic_data(diags[0])["code"] == "parser.syntax_error"


def test_parser_error_diagnostic_end_uses_utf16_columns() -> None:
    source = "rule bad { condition: 😀😀 }"
    source_start = source.index("😀")
    error = SimpleNamespace(
        line=1,
        column=source_start + 1,
        source=source,
        __str__=lambda self: "syntax",
    )

    diagnostic = parser_error_to_diagnostic(error, DiagnosticData)

    assert diagnostic.range.start.character == utf8_col_to_utf16(source, source_start)
    assert diagnostic.range.end.character == utf8_col_to_utf16(source, source_start + 10)


def test_parser_error_diagnostic_respects_empty_source_text() -> None:
    error = SimpleNamespace(
        line=1,
        column=2,
        source="😀x",
        __str__=lambda self: "syntax",
    )

    diagnostic = parser_error_to_diagnostic(error, DiagnosticData, source_text="")

    assert diagnostic.range.start.character == 1
    assert diagnostic.range.end.character == 11
    assert _diagnostic_metadata(diagnostic)["column"] == 1


def test_provider_parser_error_diagnostic_uses_source_text_for_utf16_columns() -> None:
    provider = DiagnosticsProvider()
    text = """
rule dup {
  strings:
    /* 😀😀 */ $a = "x"
    /* 😀😀 */ $a = "y"
  condition:
    $a
}
""".lstrip()
    line = text.splitlines()[3]
    duplicate_start = line.index("$a")

    diagnostics = provider.get_diagnostics(text)

    duplicate = next(
        diagnostic for diagnostic in diagnostics if diagnostic.source == "yaraast-parser"
    )
    assert duplicate.range.start.character == utf8_col_to_utf16(line, duplicate_start)
    assert duplicate.range.end.character == utf8_col_to_utf16(line, duplicate_start + 10)


def test_diagnostics_semantic_warning() -> None:
    provider = DiagnosticsProvider()
    text = """
    rule dup_strings {
        strings:
            $a = "abc"
            $a = "def"
        condition:
            $a
    }
    """.lstrip()

    diags = provider.get_diagnostics(text)
    assert diags
    duplicate = next(d for d in diags if d.code == "parser.syntax_error")
    assert duplicate.source == "yaraast-parser"
    assert "duplicated string identifier" in duplicate.message


def test_diagnostics_validation_conversion_edges() -> None:
    provider = DiagnosticsProvider()

    with_location = ValidationError(
        "warn",
        location=Location(line=2, column=3, file="x.yar"),
        severity="warning",
        suggestion="rename it",
    )
    diag = provider._validation_error_to_diagnostic(with_location, DiagnosticSeverity.Warning)
    assert diag.range.start.line == 1
    assert diag.range.start.character == 2  # Column 3 (1-based) → 2 (0-based)
    assert "Suggestion" in diag.message
    assert diag.related_information is not None

    no_location = ValidationError("warn")
    diag2 = provider._validation_error_to_diagnostic(no_location, DiagnosticSeverity.Warning)
    assert diag2.range.start.line == 0
    assert diag2.range.end.character == 1


def test_validation_error_diagnostic_range_uses_utf16_columns(tmp_path: Path) -> None:
    provider = DiagnosticsProvider()
    source = "rule bad { condition: 😀😀 }"
    source_path = tmp_path / "bad.yar"
    source_path.write_text(source, encoding="utf-8")
    source_start = source.index("😀")
    error = ValidationError(
        "warn",
        location=Location(line=1, column=source_start + 1, file=str(source_path)),
        severity="warning",
    )

    diag = provider._validation_error_to_diagnostic(error, DiagnosticSeverity.Warning)

    assert diag.range.start.character == utf8_col_to_utf16(source, source_start)
    assert diag.range.end.character == utf8_col_to_utf16(source, source_start + 10)


def test_validation_error_diagnostic_ignores_invalid_utf8_location_file(
    tmp_path: Path,
) -> None:
    provider = DiagnosticsProvider()
    source_path = tmp_path / "bad.yar"
    source_path.write_bytes(b"\xff")
    error = ValidationError(
        "warn",
        location=Location(line=1, column=3, file=str(source_path)),
        severity="warning",
    )

    diag = provider._validation_error_to_diagnostic(error, DiagnosticSeverity.Warning)

    assert diag.range.start.character == 2
    assert diag.range.end.character == 12


def test_diagnostics_unknown_function_warning() -> None:
    provider = DiagnosticsProvider()
    text = """
rule weird {
    condition:
        totally_unknown_fn()
}
""".lstrip()

    diags = provider.get_diagnostics(text)
    assert any(d.severity == 2 and d.source == "yaraast-validator" for d in diags)


def test_diagnostics_missing_import_contains_structured_patch() -> None:
    provider = DiagnosticsProvider()
    text = """
rule weird {
    condition:
        pe.imphash() == "x"
}
""".lstrip()

    diags = provider.get_diagnostics(text)
    missing_import = next(d for d in diags if d.code == "semantic.module_not_imported")
    assert _diagnostic_patches(missing_import)[0]["replacement"] == 'import "pe"\n'
    assert _diagnostic_metadata(missing_import)["module"] == "pe"


def test_diagnostics_duplicate_identifier_contains_metadata() -> None:
    provider = DiagnosticsProvider()

    duplicate = provider._validation_error_to_diagnostic(
        ValidationError("Duplicate string identifier '$a' in rule 'dup_strings'"),
        DiagnosticSeverity.Error,
    )
    assert _diagnostic_metadata(duplicate)["identifier"] == "$a"


def test_diagnostics_function_errors_include_structured_metadata() -> None:
    provider = DiagnosticsProvider()
    text = """
import "pe"

rule weird {
    condition:
        pe.missing_func()
}
""".lstrip()

    diags = provider.get_diagnostics(text)
    missing_func = next(d for d in diags if d.code == "semantic.module_function_not_found")
    missing_func_metadata = _diagnostic_metadata(missing_func)
    assert missing_func_metadata["module"] == "pe"
    assert missing_func_metadata["function"] == "missing_func"
    assert "available_functions" in missing_func_metadata

    parser_diags = provider.get_diagnostics("rule bad { condition: uint8() == 0 }")
    assert any(
        diag.code == "parser.syntax_error" and "expects exactly 1 argument" in diag.message
        for diag in parser_diags
    )


def test_diagnostics_undefined_string_identifier_is_structured() -> None:
    provider = DiagnosticsProvider()
    error = ValidationError(
        "Undefined variable $payload",
        location=Location(line=3, column=8, file="x.yar"),
    )

    diag = provider._validation_error_to_diagnostic(error, DiagnosticSeverity.Error)
    assert diag.code == "semantic.undefined_string_identifier"
    assert _diagnostic_metadata(diag)["identifier"] == "$payload"


def test_diagnostics_unknown_and_range_arity_metadata_are_structured() -> None:
    provider = DiagnosticsProvider()

    unknown = ValidationError(
        "Unknown function 'totally_unknown_fn'. If this is a module function, use 'module.totally_unknown_fn' syntax."
    )
    unknown_diag = provider._validation_error_to_diagnostic(unknown, DiagnosticSeverity.Warning)
    assert unknown_diag.code == "semantic.unknown_function"
    assert _diagnostic_metadata(unknown_diag)["function"] == "totally_unknown_fn"

    min_arity = ValidationError("Function 'uint8' expects at least 1 argument(s), got 0")
    min_diag = provider._validation_error_to_diagnostic(min_arity, DiagnosticSeverity.Error)
    assert min_diag.code == "semantic.invalid_arity"
    min_metadata = _diagnostic_metadata(min_diag)
    assert min_metadata["arity_kind"] == "min"
    assert min_metadata["expected_min"] == 1
    assert min_metadata["actual_args"] == 0

    max_arity = ValidationError("Function 'uint8' expects at most 1 argument(s), got 2")
    max_diag = provider._validation_error_to_diagnostic(max_arity, DiagnosticSeverity.Error)
    assert max_diag.code == "semantic.invalid_arity"
    max_metadata = _diagnostic_metadata(max_diag)
    assert max_metadata["arity_kind"] == "max"
    assert max_metadata["expected_max"] == 1
    assert max_metadata["actual_args"] == 2


def test_diagnostics_unknown_function_includes_suggestions() -> None:
    provider = DiagnosticsProvider()
    text = """
rule sample {
    condition:
        uint33(0)
}
""".lstrip()

    diags = provider.get_diagnostics(text)
    diag = next(d for d in diags if _diagnostic_data(d)["code"] == "semantic.unknown_function")
    metadata = _diagnostic_metadata(diag)
    assert "suggested_functions" in metadata
    assert "uint32" in metadata["suggested_functions"]


def test_metadata_validation_ignores_malformed_config_entries() -> None:
    runtime = LspRuntime()
    runtime.update_config(
        {
            "YARA": {
                "metadataValidation": [
                    "invalid-entry",
                    {"identifier": "author", "required": True},
                ]
            }
        }
    )
    provider = DiagnosticsProvider(runtime)

    diags = provider.get_diagnostics("rule missing_author { condition: true }\n", "file:///x.yar")

    assert any(d.source == "yaraast-metadata" for d in diags)


def test_metadata_validation_requires_boolean_required_flag() -> None:
    text = "rule missing_author { condition: true }\n"
    for required in ["false", "true", 1, object()]:
        runtime = LspRuntime()
        runtime.update_config(
            {
                "YARA": {
                    "metadataValidation": [
                        {"identifier": "author", "required": required},
                    ]
                }
            }
        )
        provider = DiagnosticsProvider(runtime)

        diags = provider.get_diagnostics(text, "file:///x.yar")

        assert not any(d.source == "yaraast-metadata" for d in diags)


def test_metadata_validation_ignores_non_string_identifiers() -> None:
    runtime = LspRuntime()
    runtime.update_config(
        {
            "YARA": {
                "metadataValidation": [
                    {"identifier": 123, "required": True},
                    {"identifier": "", "required": True},
                ]
            }
        }
    )
    provider = DiagnosticsProvider(runtime)

    diags = provider.get_diagnostics("rule sample { condition: true }\n", "file:///x.yar")

    assert not any(d.source == "yaraast-metadata" for d in diags)


def test_rule_name_validation_ignores_malformed_config_value() -> None:
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"ruleNameValidation": "^GOOD_"}})
    runtime.update_config({"YARA": {"ruleNameValidation": ["invalid-pattern"]}})
    provider = DiagnosticsProvider(runtime)

    diags = provider.get_diagnostics("rule bad_name { condition: true }\n", "file:///x.yar")

    assert any(d.source == "yaraast-naming" for d in diags)


def test_compiler_include_error_is_structured() -> None:
    provider = DiagnosticsProvider()
    diag = provider._compiler_error_to_diagnostic('include error: cannot open "missing.yar"')
    assert diag.code == "compiler.include_error"
    assert _diagnostic_metadata(diag)["include"] == "missing.yar"


def test_compiler_undefined_identifier_and_syntax_error_are_structured() -> None:
    provider = DiagnosticsProvider()

    undefined = provider._compiler_error_to_diagnostic(
        'Compilation error: undefined identifier "$payload"'
    )
    assert undefined.code == "compiler.undefined_identifier"
    assert _diagnostic_metadata(undefined)["identifier"] == "$payload"

    syntax = provider._compiler_error_to_diagnostic("Syntax error: unexpected '}'")
    assert syntax.code == "compiler.syntax_error"


def test_compiler_undefined_module_identifier_includes_structured_module_metadata() -> None:
    provider = DiagnosticsProvider()

    undefined = provider._compiler_error_to_diagnostic(
        'Compilation error: undefined identifier "pe"'
    )
    assert undefined.code == "compiler.module_not_imported"
    metadata = _diagnostic_metadata(undefined)
    assert metadata["identifier"] == "pe"
    assert metadata["module"] == "pe"


def test_compiler_dotted_module_identifier_includes_module_and_member_metadata() -> None:
    provider = DiagnosticsProvider()

    undefined = provider._compiler_error_to_diagnostic(
        'Compilation error: undefined identifier "pe.is_pe"'
    )
    assert undefined.code == "compiler.module_not_imported"
    metadata = _diagnostic_metadata(undefined)
    assert metadata["identifier"] == "pe.is_pe"
    assert metadata["module"] == "pe"
    assert metadata["member"] == "is_pe"
