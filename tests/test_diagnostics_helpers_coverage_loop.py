# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Coverage-gap tests for yaraast/lsp/diagnostics_helpers.py.

Each test targets one or more lines that remained uncovered after the
existing test_lsp_diagnostics_more.py and test_lsp_diagnostics_coverage_loop.py
suites ran.  All tests invoke real production functions directly — no mocks,
no monkeypatching of the module under test.

Missing lines before this file:
  39->41   parser_error_to_diagnostic — line index out of range (source has fewer lines than error.line)
  125      error_code — "include" + "error" in message → "compiler.include_error"
  146->149 patches_for_error — Duplicate string identifier match found → patch returned
  151->159 patches_for_error — Module not imported match found → import patch returned
  171      metadata_for_error — undefined variable that matches a known MODULE_DOCS key
  185->192 metadata_for_error — module_function branch: suggestion with available functions
  187->192 metadata_for_error — available functions list is non-empty
  217-218  metadata_for_error — invalid_arity with exact "expects N argument(s)" form
  222      metadata_for_error — include error match → metadata["include"] populated
"""

from __future__ import annotations

from types import SimpleNamespace

from lsprotocol.types import Position, Range

from yaraast.lsp.diagnostics import DiagnosticData, DiagnosticPatch
from yaraast.lsp.diagnostics_helpers import (
    compiler_error_to_diagnostic,
    error_code,
    metadata_for_error,
    parser_error_to_diagnostic,
    patches_for_error,
    related_info,
    suggest_builtin_functions,
)
from yaraast.types.semantic_validator_core import ValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dummy_range() -> Range:
    return Range(start=Position(line=0, character=0), end=Position(line=0, character=1))


# ---------------------------------------------------------------------------
# Line 39->41 — parser_error_to_diagnostic with out-of-range line index
# ---------------------------------------------------------------------------


def test_parser_error_line_out_of_range_falls_back_to_raw_column() -> None:
    """
    Purpose: cover branch 39->41 (condition False path).

    When error.line exceeds the number of lines in the source text, the
    inner ``if 0 <= line < len(lines)`` branch is skipped.  source_line
    remains empty, so the utf16 conversion block (line 41) is also skipped
    and the raw source_col values are used directly.

    Arrange: craft an error whose line number (5) exceeds the source line
    count (1).  The source text has a single line so lines=[source]; index 4
    is out of range.
    Act: call parser_error_to_diagnostic with that error.
    Assert: the diagnostic is returned without raising; start/end characters
    fall back to the raw column values (column - 1 and column - 1 + 10).
    """
    source = "rule bad { condition: true }"
    error = SimpleNamespace(
        line=5,  # 1-based; line-1 = 4, which is >= len(lines)=1
        column=3,
        source=source,
        __str__=lambda self: "syntax error",
    )

    diagnostic = parser_error_to_diagnostic(error, DiagnosticData)

    # source_line stays empty → raw fallback: start_col = column - 1 = 2
    assert diagnostic.range.start.character == 2
    assert diagnostic.range.end.character == 12


# ---------------------------------------------------------------------------
# Line 125 — error_code with include + error in message
# ---------------------------------------------------------------------------


def test_error_code_include_error_message() -> None:
    """
    Purpose: cover line 125 — the ``return "compiler.include_error"`` branch.

    error_code() falls through every preceding keyword check and reaches the
    include/error guard only when:
      - the message does NOT contain "undefined variable"
      - the message does NOT contain "duplicate string identifier"
      - the message does NOT contain "not imported"
      - the message does NOT contain "function '" + "not found in module"
      - the message does NOT contain "expects" + "argument"
      - the message does NOT contain "unknown function"
      - the message DOES contain both "include" and "error"

    Arrange: build a ValidationError whose .message satisfies all of the
    above conditions.
    Act: call error_code().
    Assert: returns "compiler.include_error".
    """
    error = ValidationError("include file error: file not found")

    result = error_code(error)

    assert result == "compiler.include_error"


def test_error_code_falls_through_to_validation_error() -> None:
    """
    Purpose: confirm the default branch (line 126) is also reachable as a
    control: a message that matches none of the specific patterns returns
    "semantic.validation_error".
    """
    error = ValidationError("something completely unrecognized happened")

    result = error_code(error)

    assert result == "semantic.validation_error"


# ---------------------------------------------------------------------------
# Lines 146->149 — patches_for_error: duplicate string identifier match
# ---------------------------------------------------------------------------


def test_patches_for_error_duplicate_string_identifier_returns_patch() -> None:
    """
    Purpose: cover lines 146->149.

    When the error message contains "Duplicate string identifier" and the
    regex ``r"'\\$(\\w+)'"`` matches, patches_for_error must return a list
    containing one patch whose replacement is the original identifier with
    a ``_2`` suffix.

    Arrange: construct a ValidationError mirroring the real validator output
    and supply a real DiagnosticPatch class.
    Act: call patches_for_error.
    Assert: one patch is returned; its replacement is "$myvar_2".
    """
    error = ValidationError("Duplicate string identifier '$myvar' in rule 'test_rule'")
    diag_range = _dummy_range()

    patches = patches_for_error(error, diag_range, DiagnosticPatch)

    assert len(patches) == 1
    patch = patches[0]
    assert isinstance(patch, DiagnosticPatch)
    assert patch.replacement == "$myvar_2"
    assert patch.range is diag_range


def test_patches_for_error_duplicate_string_no_regex_match_returns_empty() -> None:
    """
    Purpose: confirm the branch where "Duplicate string identifier" is present
    but the regex does NOT match (no ``'$…'`` portion) — returns empty list.
    """
    error = ValidationError("Duplicate string identifier without a quoted name")
    diag_range = _dummy_range()

    patches = patches_for_error(error, diag_range, DiagnosticPatch)

    assert patches == []


# ---------------------------------------------------------------------------
# Lines 151->159 — patches_for_error: module not imported import patch
# ---------------------------------------------------------------------------


def test_patches_for_error_module_not_imported_returns_import_patch() -> None:
    """
    Purpose: cover lines 151->159.

    When the message contains "Module '" and "not imported" and the module
    name regex matches, patches_for_error returns one patch that inserts an
    ``import "module_name"\\n`` at the top of the file (line 0, char 0).

    Arrange: build a ValidationError matching the Module not imported pattern.
    Act: call patches_for_error.
    Assert: one patch with the correct import statement at position (0,0).
    """
    error = ValidationError("Module 'pe' not imported")
    diag_range = _dummy_range()

    patches = patches_for_error(error, diag_range, DiagnosticPatch)

    assert len(patches) == 1
    patch = patches[0]
    assert isinstance(patch, DiagnosticPatch)
    assert patch.replacement == 'import "pe"\n'
    # The patch must target the very start of the document
    assert patch.range.start.line == 0
    assert patch.range.start.character == 0
    assert patch.range.end.line == 0
    assert patch.range.end.character == 0


def test_patches_for_error_module_not_imported_no_regex_match_returns_empty() -> None:
    """
    Purpose: verify that "Module '" and "not imported" without a word-boundary
    module name in the expected position returns an empty list because the
    more-specific regex inside the branch does not match.
    """
    error = ValidationError("Module '' not imported")
    diag_range = _dummy_range()

    # re.search(r"Module '(\w+)' not imported", ...) needs at least one \w char
    patches = patches_for_error(error, diag_range, DiagnosticPatch)

    assert patches == []


# ---------------------------------------------------------------------------
# Line 171 — metadata_for_error: undefined variable that is a MODULE_DOCS key
# ---------------------------------------------------------------------------


def test_metadata_for_error_undefined_variable_matching_module_doc_key() -> None:
    """
    Purpose: cover line 171 — ``metadata["module"] = identifier``.

    The undefined-variable regex matches a name that does NOT start with ``$``
    (not a string identifier) and IS present in MODULE_DOCS.  In that case
    metadata_for_error sets both ``identifier`` and ``module`` to the same
    value.

    Arrange: "pe" is a key in MODULE_DOCS (verified above).  Build a
    ValidationError whose message looks like "Undefined variable pe".
    Act: call metadata_for_error.
    Assert: metadata["identifier"] == "pe" and metadata["module"] == "pe".
    """
    error = ValidationError("Undefined variable pe")

    metadata = metadata_for_error(error)

    assert metadata["identifier"] == "pe"
    assert metadata["module"] == "pe"


def test_metadata_for_error_undefined_string_var_does_not_set_module() -> None:
    """
    Purpose: confirm that an identifier starting with ``$`` does NOT trigger
    line 171.

    When the undefined-variable pattern matches ``$payload`` the ``startswith``
    guard short-circuits and ``module`` is never added to metadata.
    """
    error = ValidationError("Undefined variable $payload")

    metadata = metadata_for_error(error)

    assert metadata["identifier"] == "$payload"
    assert "module" not in metadata


# ---------------------------------------------------------------------------
# Lines 185->192, 187->192 — metadata_for_error: module function with
#   available functions in suggestion
# ---------------------------------------------------------------------------


def test_metadata_for_error_module_function_with_available_functions() -> None:
    """
    Purpose: cover lines 185->192 and 187->192.

    When the error message matches the ``Function '…' not found in module '…'``
    pattern and ``error.suggestion`` starts with "Available functions: " and
    has non-empty content after that prefix, the helper populates
    ``metadata["available_functions"]`` with a list of stripped names.

    Arrange: build a ValidationError whose message matches the module-function
    regex and whose suggestion lists real pe module functions.
    Act: call metadata_for_error.
    Assert: metadata contains function, module, and available_functions.
    """
    error = ValidationError(
        "Function 'missing_func' not found in module 'pe'",
        suggestion="Available functions: imphash, exports, imports",
    )

    metadata = metadata_for_error(error)

    assert metadata["function"] == "missing_func"
    assert metadata["module"] == "pe"
    assert "available_functions" in metadata
    available = metadata["available_functions"]
    assert isinstance(available, list)
    assert "imphash" in available
    assert "exports" in available
    assert "imports" in available


def test_metadata_for_error_module_function_suggestion_empty_after_strip() -> None:
    """
    Purpose: cover line 185->192 branch taken but 187->192 branch NOT taken.

    When suggestion starts with "Available functions: " but the remainder is
    whitespace-only, ``available`` is empty after strip so
    ``available_functions`` must NOT be set.
    """
    error = ValidationError(
        "Function 'missing_func' not found in module 'pe'",
        suggestion="Available functions:   ",
    )

    metadata = metadata_for_error(error)

    assert metadata["function"] == "missing_func"
    assert metadata["module"] == "pe"
    assert "available_functions" not in metadata


def test_metadata_for_error_module_function_no_suggestion() -> None:
    """
    Purpose: confirm the guard ``if error.suggestion and …`` is False when
    suggestion is None — available_functions must not appear.
    """
    error = ValidationError(
        "Function 'missing_func' not found in module 'pe'",
        suggestion=None,
    )

    metadata = metadata_for_error(error)

    assert metadata["function"] == "missing_func"
    assert metadata["module"] == "pe"
    assert "available_functions" not in metadata


# ---------------------------------------------------------------------------
# Lines 217-218 — metadata_for_error: exact arity "expects N argument(s)"
# ---------------------------------------------------------------------------


def test_metadata_for_error_exact_arity_sets_arity_kind_exact() -> None:
    """
    Purpose: cover lines 217-218.

    When the arity message uses the ``expects N argument(s)`` form (no
    "at least" or "at most"), the helper sets arity_kind="exact" and
    expected_args to the integer N.

    The message must also match the outer regex
    ``r"Function '(\\w+)' expects .* got (\\d+)"`` so that the
    invalid_arity block is entered at all.

    Arrange: craft a message that matches the outer pattern AND the exact
    sub-pattern but NOT the at-least or at-most sub-patterns.
    Act: call metadata_for_error.
    Assert: arity_kind == "exact" and expected_args == 1.
    """
    error = ValidationError("Function 'uint8' expects 1 argument(s), got 0")

    metadata = metadata_for_error(error)

    assert metadata["function"] == "uint8"
    assert metadata["actual_args"] == 0
    assert metadata["arity_kind"] == "exact"
    assert metadata["expected_args"] == 1


def test_metadata_for_error_at_least_arity_does_not_set_exact() -> None:
    """
    Purpose: confirm that "at least" form does NOT set arity_kind="exact".

    The message must contain "at least N argument" which hits the at_least
    branch; the exact sub-regex must not match so expected_args is absent.
    """
    error = ValidationError("Function 'uint8' expects at least 1 argument(s), got 0")

    metadata = metadata_for_error(error)

    assert metadata["arity_kind"] == "min"
    assert metadata["expected_min"] == 1
    assert "expected_args" not in metadata


# ---------------------------------------------------------------------------
# Line 222 — metadata_for_error: include error populates metadata["include"]
# ---------------------------------------------------------------------------


def test_metadata_for_error_include_error_populates_include_key() -> None:
    """
    Purpose: cover line 222.

    When the error message matches the include-file regex
    ``r"include.*?['\\\"]([^'\\\"]+)['\\\"]"`` (case-insensitive),
    metadata["include"] is set to the captured filename.

    Arrange: build a ValidationError whose message looks like a typical
    include-file error.
    Act: call metadata_for_error.
    Assert: metadata["include"] equals the captured filename.
    """
    error = ValidationError('include "missing_file.yar": file not found')

    metadata = metadata_for_error(error)

    assert metadata["include"] == "missing_file.yar"


def test_metadata_for_error_include_single_quotes_populates_include_key() -> None:
    """
    Purpose: cover line 222 via single-quoted filename variant.

    The regex accepts both single and double quotes.
    """
    error = ValidationError("Include 'another/file.yar' could not be opened")

    metadata = metadata_for_error(error)

    assert metadata["include"] == "another/file.yar"


# ---------------------------------------------------------------------------
# Additional coverage: related_info — location.file is falsy
# ---------------------------------------------------------------------------


def test_related_info_returns_none_when_location_file_is_empty() -> None:
    """
    Purpose: verify related_info returns None when location.file is an empty
    string (falsy but not None).

    This exercises the guard ``not error.location.file``.
    """
    location = SimpleNamespace(file="")
    error = SimpleNamespace(
        message="some error",
        location=location,
    )

    result = related_info(error, _dummy_range())

    assert result is None


def test_related_info_returns_none_when_location_is_none() -> None:
    """
    Purpose: verify related_info returns None when error.location is None.

    This exercises the ``not error.location`` guard.
    """
    error = SimpleNamespace(message="some error", location=None)

    result = related_info(error, _dummy_range())

    assert result is None


def test_related_info_returns_list_when_location_file_is_present() -> None:
    """
    Purpose: verify related_info returns a populated list when both
    error.location and error.location.file are truthy.
    """
    location = SimpleNamespace(file="file:///rule.yar")
    error = SimpleNamespace(message="some error", location=location)
    diag_range = _dummy_range()

    result = related_info(error, diag_range)

    assert result is not None
    assert len(result) == 1
    assert result[0].message == "some error"
    assert result[0].location.uri == "file:///rule.yar"
    assert result[0].location.range is diag_range


# ---------------------------------------------------------------------------
# suggest_builtin_functions: fuzzy matching boundary cases
# ---------------------------------------------------------------------------


def test_suggest_builtin_functions_returns_close_match() -> None:
    """
    Purpose: validate that suggest_builtin_functions returns close matches
    for a near-miss builtin name.

    "uint33" is not a real builtin; "uint32" and "uint32be" should score
    above the 0.5 cutoff and appear in suggestions.
    """
    suggestions = suggest_builtin_functions("uint33")

    assert len(suggestions) >= 1
    assert "uint32" in suggestions


def test_suggest_builtin_functions_returns_empty_for_unrelated_name() -> None:
    """
    Purpose: validate that suggest_builtin_functions returns an empty list
    for a name that shares no similarity with any builtin.
    """
    suggestions = suggest_builtin_functions("xyzzy_completely_unrelated")

    assert suggestions == []


# ---------------------------------------------------------------------------
# compiler_error_to_diagnostic: undefined identifier that is a module member
# ---------------------------------------------------------------------------


def test_compiler_error_undefined_identifier_module_member_sets_member_key() -> None:
    """
    Purpose: cover lines 81-84 of compiler_error_to_diagnostic.

    When the undefined-identifier name is of the form ``module.member`` and
    the module part (but not the full name) is in MODULE_DOCS, the function
    sets code to "compiler.module_not_imported" and metadata includes both
    ``module`` and ``member`` keys.

    Arrange: craft a message referencing "pe.imphash" where "pe" is in
    MODULE_DOCS but "pe.imphash" is not.
    Act: call compiler_error_to_diagnostic.
    Assert: code is "compiler.module_not_imported"; metadata has the
    expected module and member entries.
    """
    message = "undefined identifier: 'pe.imphash'"

    diagnostic = compiler_error_to_diagnostic(message, DiagnosticData)

    assert diagnostic.code == "compiler.module_not_imported"
    data = diagnostic.data
    assert isinstance(data, dict)
    assert data["metadata"]["module"] == "pe"
    assert data["metadata"]["member"] == "imphash"


def test_compiler_error_undefined_identifier_full_module_name_sets_module_key() -> None:
    """
    Purpose: cover lines 78-80 of compiler_error_to_diagnostic.

    When the entire identifier (without a dot) is a MODULE_DOCS key, the
    code is "compiler.module_not_imported" and metadata["module"] is the
    identifier itself.
    """
    message = "undefined identifier: 'pe'"

    diagnostic = compiler_error_to_diagnostic(message, DiagnosticData)

    assert diagnostic.code == "compiler.module_not_imported"
    data = diagnostic.data
    assert isinstance(data, dict)
    assert data["metadata"]["module"] == "pe"
    assert "member" not in data["metadata"]


def test_compiler_error_syntax_error_sets_correct_code() -> None:
    """
    Purpose: cover the syntax_error branch in compiler_error_to_diagnostic.
    """
    message = "syntax error, unexpected $end"

    diagnostic = compiler_error_to_diagnostic(message, DiagnosticData)

    assert diagnostic.code == "compiler.syntax_error"


def test_compiler_error_include_error_sets_include_metadata() -> None:
    """
    Purpose: cover the include_error branch in compiler_error_to_diagnostic.
    """
    message = 'include "bad_file.yar" could not be opened'

    diagnostic = compiler_error_to_diagnostic(message, DiagnosticData)

    assert diagnostic.code == "compiler.include_error"
    data = diagnostic.data
    assert isinstance(data, dict)
    assert data["metadata"]["include"] == "bad_file.yar"
