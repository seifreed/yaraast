"""Real tests for LSP diagnostics (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import Location
from yaraast.lsp.diagnostics import DiagnosticsProvider
from yaraast.types.semantic_validator_core import ValidationError


def test_diagnostics_parser_error() -> None:
    provider = DiagnosticsProvider()
    text = "rule bad { condition: "

    diags = provider.get_diagnostics(text)
    assert diags
    assert diags[0].source in {"yaraast-parser", "yaraast"}
    assert diags[0].code == "parser.syntax_error"
    assert diags[0].data["code"] == "parser.syntax_error"


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
    # Expect at least one warning or error for duplicate identifier
    assert any(d.source == "yaraast-validator" for d in diags)
    duplicate = next(d for d in diags if d.code == "semantic.duplicate_string_identifier")
    assert duplicate.data["patches"]


def test_diagnostics_validation_conversion_edges() -> None:
    provider = DiagnosticsProvider()

    with_location = ValidationError(
        "warn",
        location=Location(line=2, column=3, file="x.yar"),
        severity="warning",
        suggestion="rename it",
    )
    diag = provider._validation_error_to_diagnostic(with_location, 2)
    assert diag.range.start.line == 1
    assert diag.range.start.character == 2  # Column 3 (1-based) → 2 (0-based)
    assert "Suggestion" in diag.message
    assert diag.related_information is not None

    no_location = ValidationError("warn")
    diag2 = provider._validation_error_to_diagnostic(no_location, 2)
    assert diag2.range.start.line == 0
    assert diag2.range.end.character == 1


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
    assert missing_import.data["patches"][0]["replacement"] == 'import "pe"\n'
    assert missing_import.data["metadata"]["module"] == "pe"


def test_diagnostics_duplicate_identifier_contains_metadata() -> None:
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
    duplicate = next(d for d in diags if d.code == "semantic.duplicate_string_identifier")
    assert duplicate.data["metadata"]["identifier"] == "$a"


def test_diagnostics_function_errors_include_structured_metadata() -> None:
    provider = DiagnosticsProvider()
    text = """
import "pe"

rule weird {
    condition:
        pe.missing_func() and uint8()
}
""".lstrip()

    diags = provider.get_diagnostics(text)
    missing_func = next(d for d in diags if d.code == "semantic.module_function_not_found")
    invalid_arity = next(d for d in diags if d.code == "semantic.invalid_arity")
    assert missing_func.data["metadata"]["module"] == "pe"
    assert missing_func.data["metadata"]["function"] == "missing_func"
    assert "available_functions" in missing_func.data["metadata"]
    assert invalid_arity.data["metadata"]["function"] == "uint8"
    assert invalid_arity.data["metadata"]["actual_args"] == 0
    assert invalid_arity.data["metadata"]["arity_kind"] == "min"
    assert invalid_arity.data["metadata"]["expected_min"] == 1


def test_diagnostics_undefined_string_identifier_is_structured() -> None:
    provider = DiagnosticsProvider()
    error = ValidationError(
        "Undefined variable $payload",
        location=Location(line=3, column=8, file="x.yar"),
    )

    diag = provider._validation_error_to_diagnostic(error, 1)
    assert diag.code == "semantic.undefined_string_identifier"
    assert diag.data["metadata"]["identifier"] == "$payload"


def test_diagnostics_unknown_and_range_arity_metadata_are_structured() -> None:
    provider = DiagnosticsProvider()

    unknown = ValidationError(
        "Unknown function 'totally_unknown_fn'. If this is a module function, use 'module.totally_unknown_fn' syntax."
    )
    unknown_diag = provider._validation_error_to_diagnostic(unknown, 2)
    assert unknown_diag.code == "semantic.unknown_function"
    assert unknown_diag.data["metadata"]["function"] == "totally_unknown_fn"

    min_arity = ValidationError("Function 'uint8' expects at least 1 argument(s), got 0")
    min_diag = provider._validation_error_to_diagnostic(min_arity, 1)
    assert min_diag.code == "semantic.invalid_arity"
    assert min_diag.data["metadata"]["arity_kind"] == "min"
    assert min_diag.data["metadata"]["expected_min"] == 1
    assert min_diag.data["metadata"]["actual_args"] == 0

    max_arity = ValidationError("Function 'uint8' expects at most 1 argument(s), got 2")
    max_diag = provider._validation_error_to_diagnostic(max_arity, 1)
    assert max_diag.code == "semantic.invalid_arity"
    assert max_diag.data["metadata"]["arity_kind"] == "max"
    assert max_diag.data["metadata"]["expected_max"] == 1
    assert max_diag.data["metadata"]["actual_args"] == 2


def test_diagnostics_unknown_function_includes_suggestions() -> None:
    provider = DiagnosticsProvider()
    text = """
rule sample {
    condition:
        uint33(0)
}
""".lstrip()

    diags = provider.get_diagnostics(text)
    diag = next(d for d in diags if d.data and d.data["code"] == "semantic.unknown_function")
    assert "suggested_functions" in diag.data["metadata"]
    assert "uint32" in diag.data["metadata"]["suggested_functions"]


def test_compiler_include_error_is_structured() -> None:
    provider = DiagnosticsProvider()
    diag = provider._compiler_error_to_diagnostic('include error: cannot open "missing.yar"')
    assert diag.code == "compiler.include_error"
    assert diag.data["metadata"]["include"] == "missing.yar"


def test_compiler_undefined_identifier_and_syntax_error_are_structured() -> None:
    provider = DiagnosticsProvider()

    undefined = provider._compiler_error_to_diagnostic(
        'Compilation error: undefined identifier "$payload"'
    )
    assert undefined.code == "compiler.undefined_identifier"
    assert undefined.data["metadata"]["identifier"] == "$payload"

    syntax = provider._compiler_error_to_diagnostic("Syntax error: unexpected '}'")
    assert syntax.code == "compiler.syntax_error"


def test_compiler_undefined_module_identifier_includes_structured_module_metadata() -> None:
    provider = DiagnosticsProvider()

    undefined = provider._compiler_error_to_diagnostic(
        'Compilation error: undefined identifier "pe"'
    )
    assert undefined.code == "compiler.module_not_imported"
    assert undefined.data["metadata"]["identifier"] == "pe"
    assert undefined.data["metadata"]["module"] == "pe"


def test_compiler_dotted_module_identifier_includes_module_and_member_metadata() -> None:
    provider = DiagnosticsProvider()

    undefined = provider._compiler_error_to_diagnostic(
        'Compilation error: undefined identifier "pe.is_pe"'
    )
    assert undefined.code == "compiler.module_not_imported"
    assert undefined.data["metadata"]["identifier"] == "pe.is_pe"
    assert undefined.data["metadata"]["module"] == "pe"
    assert undefined.data["metadata"]["member"] == "is_pe"
