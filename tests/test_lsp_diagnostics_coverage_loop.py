"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Coverage-gap tests for yaraast/lsp/diagnostics.py.

Each test targets one or more lines that remained uncovered after the
existing test_lsp_diagnostics_more.py suite ran.  All tests use real
production paths: real parser, real validator, real runtime, real
document cache — no mocks.
"""

from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace
from typing import Any, cast

from lsprotocol.types import DiagnosticSeverity
import pytest

from yaraast.ast.base import YaraFile
from yaraast.lsp.diagnostics import DiagnosticsProvider, _location_source_line
from yaraast.lsp.document_types import RuntimeConfig
from yaraast.lsp.runtime import LspRuntime

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provider_with_runtime(settings: dict[str, Any]) -> tuple[DiagnosticsProvider, LspRuntime]:
    """Create a DiagnosticsProvider backed by a real LspRuntime with the given YARA settings."""
    runtime = LspRuntime()
    runtime.update_config({"YARA": settings})
    return DiagnosticsProvider(runtime), runtime


# ---------------------------------------------------------------------------
# Line 114 — cache hit: second call returns cached diagnostics
# ---------------------------------------------------------------------------


def test_diagnostics_cache_hit_returns_same_result() -> None:
    """
    Purpose: cover line 114 (return list(cached)).

    get_diagnostics with a runtime+uri stores diagnostics on the first call.
    The second call must find the cached value and return early without
    re-parsing or re-validating.
    """
    provider, _ = _make_provider_with_runtime({})
    uri = "file:///cached_sample.yar"
    text = "rule cached_sample { condition: true }\n"

    # Arrange: first call populates the cache
    first = provider.get_diagnostics(text, uri)

    # Act: second call should hit the cache path
    second = provider.get_diagnostics(text, uri)

    # Assert: identical diagnostics (both empty for a valid rule)
    assert first == second
    assert first == []


def test_diagnostics_cache_invalidated_on_text_change() -> None:
    """
    Purpose: ensure the cache is bypassed when the document text changes.

    This exercises the set_cached / revision_key machinery and confirms that
    get_diagnostics does NOT return stale cached results.
    """
    provider, _ = _make_provider_with_runtime({})
    uri = "file:///mutation_test.yar"
    valid_text = "rule mutation_test { condition: true }\n"
    broken_text = "rule mutation_test { condition: "

    first = provider.get_diagnostics(valid_text, uri)
    assert first == []

    second = provider.get_diagnostics(broken_text, uri)
    assert len(second) == 1
    assert second[0].severity == DiagnosticSeverity.Error


# ---------------------------------------------------------------------------
# Line 134->136 — non-YARA dialect skips semantic validation
# ---------------------------------------------------------------------------


def test_diagnostics_yaral_dialect_skips_semantic_validation() -> None:
    """
    Purpose: cover the branch 134->136 (dialect not in {None, YARA}).

    When the runtime is configured for YARA-L (dialectMode=yara-l), parsing
    a document that would trigger a YARA semantic error must produce no
    diagnostic from the semantic validator — the validation block is skipped.
    """
    provider, _ = _make_provider_with_runtime({"dialectMode": "yara-l"})
    uri = "file:///test_yaral.yaral"
    # This would produce 'unknown_function' under classic YARA but is ignored for YARAL
    text = "rule sample { condition: unknown_fn() }"

    diags = provider.get_diagnostics(text, uri)

    # No semantic validator diagnostics emitted for YARAL dialect
    assert not any(d.source == "yaraast-validator" for d in diags)


def test_diagnostics_yarax_dialect_skips_semantic_validation() -> None:
    """
    Purpose: cover branch 134->136 via the YARA-X dialect.

    Same invariant: non-YARA dialect bypasses the semantic validator entirely.
    """
    provider, _ = _make_provider_with_runtime({"dialectMode": "yarax"})
    uri = "file:///test_yarax.yar"
    text = "rule sample { condition: true }"

    diags = provider.get_diagnostics(text, uri)

    assert not any(d.source == "yaraast-validator" for d in diags)


# ---------------------------------------------------------------------------
# Line 173 — compiler path (no validation errors, compilation fails)
# ---------------------------------------------------------------------------


def test_diagnostics_compiler_path_reached_when_no_validation_errors() -> None:
    """
    Purpose: cover line 173 (diagnostics.extend from compiler errors).

    When a rule passes semantic validation but fails libyara compilation
    (e.g. includes are disabled), the compiler error must appear in the
    returned diagnostics.

    Preconditions: YARA_AVAILABLE must be True; otherwise compiler is None
    and this branch is structurally unreachable.
    """
    from yaraast.libyara.compiler import YARA_AVAILABLE

    if not YARA_AVAILABLE:
        pytest.skip("libyara (yara-python) is not installed")

    provider = DiagnosticsProvider()
    assert provider.compiler is not None

    # An include statement passes the yaraast semantic validator but libyara
    # rejects it with 'includes are disabled'.
    text = 'include "nonexistent.yar"\nrule include_test { condition: true }'

    diags = provider.get_diagnostics(text)

    assert len(diags) >= 1
    compiler_diag = next(
        (d for d in diags if d.source == "yaraast-compiler"),
        None,
    )
    assert compiler_diag is not None, "expected a compiler diagnostic"
    assert compiler_diag.severity == DiagnosticSeverity.Error


# ---------------------------------------------------------------------------
# Lines 302->309, 338-342 — metadata type validation: type mismatch warning
# ---------------------------------------------------------------------------


def test_metadata_type_mismatch_emits_warning() -> None:
    """
    Purpose: cover lines 338-342 (type mismatch diagnostic) and the
    302->309 branch (checker is not None but value fails the type check).

    A rule with metadata 'severity' set to a string when 'int' is expected
    must produce a yaraast-metadata warning.
    """
    provider, _ = _make_provider_with_runtime(
        {"metadataValidation": [{"identifier": "severity", "type": "int"}]}
    )
    uri = "file:///type_mismatch.yar"
    text = 'rule type_mismatch { meta: severity = "high" condition: true }\n'

    diags = provider.get_diagnostics(text, uri)

    mismatch = [d for d in diags if d.source == "yaraast-metadata"]
    assert len(mismatch) == 1
    assert "should be of type" in mismatch[0].message
    assert "severity" in mismatch[0].message
    assert mismatch[0].severity == DiagnosticSeverity.Warning


def test_metadata_type_boolean_mismatch_emits_warning() -> None:
    """
    Purpose: additional coverage of the type-mismatch branch using 'boolean'.

    A rule with metadata 'active' as an integer when 'boolean' is expected
    must produce a yaraast-metadata type-mismatch warning.
    """
    provider, _ = _make_provider_with_runtime(
        {"metadataValidation": [{"identifier": "active", "type": "boolean"}]}
    )
    uri = "file:///bool_mismatch.yar"
    text = "rule bool_mismatch { meta: active = 1 condition: true }\n"

    diags = provider.get_diagnostics(text, uri)

    mismatch = [d for d in diags if d.source == "yaraast-metadata"]
    assert len(mismatch) == 1
    assert "should be of type 'boolean'" in mismatch[0].message


def test_metadata_unknown_type_name_emits_no_warning() -> None:
    """
    Purpose: cover branch 302->309 where checker is None (type name not in
    the type_checkers dict).

    When the validation config specifies an unknown type (e.g. 'uuid'), no
    diagnostic must be produced — the code silently skips the check.
    """
    provider, _ = _make_provider_with_runtime(
        {"metadataValidation": [{"identifier": "author", "type": "uuid"}]}
    )
    uri = "file:///unknown_type.yar"
    text = 'rule unknown_type { meta: author = "alice" condition: true }\n'

    diags = provider.get_diagnostics(text, uri)

    assert not any(d.source == "yaraast-metadata" for d in diags)


def test_metadata_non_string_type_value_emits_no_warning() -> None:
    """
    Purpose: cover line 339 — 'continue' when expected_type is not a str.

    Passing an integer as 'type' in the config must be silently ignored:
    the check is skipped and no diagnostic emitted.
    """
    provider, _ = _make_provider_with_runtime(
        {"metadataValidation": [{"identifier": "author", "type": 99}]}
    )
    uri = "file:///nonstr_type.yar"
    text = 'rule nonstr_type { meta: author = "alice" condition: true }\n'

    diags = provider.get_diagnostics(text, uri)

    assert not any(d.source == "yaraast-metadata" for d in diags)


# ---------------------------------------------------------------------------
# Lines 311->316, 313->316 — metadata validation with missing rule location
# ---------------------------------------------------------------------------


def test_validate_metadata_rule_without_location_defaults_to_line_zero() -> None:
    """
    Purpose: cover branches 311->316 and 313->316.

    These guards exist for synthetic/incomplete AST nodes where 'location'
    is None or 'line' is None.  We invoke _validate_metadata directly with
    such objects to exercise both branches, confirming rule_line defaults to 0.
    """
    provider = DiagnosticsProvider()
    config = RuntimeConfig(metadata_validation=[{"identifier": "author", "required": True}])

    # Rule with location=None
    rule_no_loc = SimpleNamespace(name="sample_no_loc", meta=[], location=None)
    ast_no_loc = cast(YaraFile, SimpleNamespace(rules=[rule_no_loc]))
    diags_no_loc = provider._validate_metadata(ast_no_loc, config)
    assert len(diags_no_loc) == 1
    assert diags_no_loc[0].range.start.line == 0

    # Rule with location but line attribute is None
    loc_no_line = SimpleNamespace(line=None)
    rule_no_line = SimpleNamespace(name="sample_no_line", meta=[], location=loc_no_line)
    ast_no_line = cast(YaraFile, SimpleNamespace(rules=[rule_no_line]))
    diags_no_line = provider._validate_metadata(ast_no_line, config)
    assert len(diags_no_line) == 1
    assert diags_no_line[0].range.start.line == 0


# ---------------------------------------------------------------------------
# Lines 359, 362-363 — rule name validation with invalid regex
# ---------------------------------------------------------------------------


def test_rule_name_validation_invalid_regex_returns_no_diagnostics() -> None:
    """
    Purpose: cover lines 359 and 362-363 (re.error handler in _validate_rule_names).

    An unparseable regex must not raise — the method catches re.error and
    returns an empty list.
    """
    provider, _ = _make_provider_with_runtime({"ruleNameValidation": "[invalid("})
    uri = "file:///invalid_re.yar"
    text = "rule invalid_re { condition: true }\n"

    diags = provider.get_diagnostics(text, uri)

    assert not any(d.source == "yaraast-naming" for d in diags)


# ---------------------------------------------------------------------------
# Line 365->364 — rule name matches pattern (no diagnostic emitted)
# ---------------------------------------------------------------------------


def test_rule_name_matching_pattern_emits_no_diagnostic() -> None:
    """
    Purpose: cover branch 365->364 (rule.name matches pattern, loop body skipped).

    When a rule name satisfies the configured regex, _validate_rule_names
    must not append any diagnostic for that rule.
    """
    provider, _ = _make_provider_with_runtime({"ruleNameValidation": "^GOOD_"})
    uri = "file:///good_name.yar"
    text = "rule GOOD_rule { condition: true }\n"

    diags = provider.get_diagnostics(text, uri)

    assert not any(d.source == "yaraast-naming" for d in diags)


def test_rule_name_mixed_matching_and_violating() -> None:
    """
    Purpose: cover both the matching (365->364) and violating branches in a
    single get_diagnostics call with two rules.

    Only the non-matching rule must produce a diagnostic.
    """
    provider, _ = _make_provider_with_runtime({"ruleNameValidation": "^GOOD_"})
    uri = "file:///mixed_names.yar"
    text = "rule GOOD_rule { condition: true }\n" "rule BAD_rule { condition: true }\n"

    diags = provider.get_diagnostics(text, uri)

    naming = [d for d in diags if d.source == "yaraast-naming"]
    assert len(naming) == 1
    assert "BAD_rule" in naming[0].message


# ---------------------------------------------------------------------------
# Lines 368->372, 370->372 — rule name violation, rule lacks location
# ---------------------------------------------------------------------------


def test_validate_rule_names_rule_without_location_defaults_to_line_zero() -> None:
    """
    Purpose: cover branches 368->372 and 370->372.

    When a rule violates the naming pattern and has no location or a location
    without a valid line, the diagnostic range must default to line 0.
    """
    provider = DiagnosticsProvider()

    # Rule with location=None
    rule_no_loc = SimpleNamespace(name="BAD_rule", location=None)
    ast_no_loc = cast(YaraFile, SimpleNamespace(rules=[rule_no_loc]))
    diags_no_loc = provider._validate_rule_names(ast_no_loc, "^GOOD_")
    assert len(diags_no_loc) == 1
    assert diags_no_loc[0].range.start.line == 0
    assert "BAD_rule" in diags_no_loc[0].message

    # Rule with a location object but .line is None
    loc_no_line = SimpleNamespace(line=None)
    rule_no_line = SimpleNamespace(name="BAD_rule", location=loc_no_line)
    ast_no_line = cast(YaraFile, SimpleNamespace(rules=[rule_no_line]))
    diags_no_line = provider._validate_rule_names(ast_no_line, "^GOOD_")
    assert len(diags_no_line) == 1
    assert diags_no_line[0].range.start.line == 0


# ---------------------------------------------------------------------------
# Line 399 — _location_source_line: line index out of bounds
# ---------------------------------------------------------------------------


def test_location_source_line_out_of_bounds_returns_empty_string() -> None:
    """
    Purpose: cover line 399 (return '' when line index >= len(lines)).

    _location_source_line must return '' when the requested line number
    exceeds the number of lines in the file.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yar", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write("rule sample { condition: true }")
        tmp_path = tmp.name

    try:
        location = SimpleNamespace(file=tmp_path)
        result = _location_source_line(location, 9999)
    finally:
        os.unlink(tmp_path)

    assert result == ""


def test_location_source_line_valid_line_returns_content() -> None:
    """
    Purpose: confirm the happy path of _location_source_line returns the
    correct line content when the index is in bounds.

    This ensures the out-of-bounds test above is not a trivially wrong
    implementation (e.g. always returning '').
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yar", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write("rule sample { condition: true }")
        tmp_path = tmp.name

    try:
        location = SimpleNamespace(file=tmp_path)
        result = _location_source_line(location, 0)
    finally:
        os.unlink(tmp_path)

    assert result == "rule sample { condition: true }"


# ---------------------------------------------------------------------------
# Line 290 — _validate_metadata early return when ast is None
# ---------------------------------------------------------------------------


def test_validate_metadata_none_ast_returns_empty_list() -> None:
    """
    Purpose: cover line 290 (early return when ast is None or has no 'rules').

    _validate_metadata guards against None or incomplete AST objects.
    Both inputs must return an empty list without raising.
    """
    provider = DiagnosticsProvider()
    config = RuntimeConfig(metadata_validation=[{"identifier": "author", "required": True}])

    # ast is None — cast to YaraFile to exercise the defensive None check
    result_none = provider._validate_metadata(cast(YaraFile, None), config)
    assert result_none == []

    # ast exists but has no 'rules' attribute — same defensive guard
    result_no_rules = provider._validate_metadata(cast(YaraFile, object()), config)
    assert result_no_rules == []


# ---------------------------------------------------------------------------
# Line 302->309 — meta attribute is not a list (skips entry loop)
# ---------------------------------------------------------------------------


def test_validate_metadata_non_list_meta_skips_entry_loop() -> None:
    """
    Purpose: cover branch 302->309 (isinstance(meta, list) is False).

    When a rule object has a 'meta' attribute that is not a list (e.g. None,
    a dict, or an int), the for-entry loop is skipped.  The rule should still
    produce a 'missing required' diagnostic because meta_dict remains empty.
    """
    provider = DiagnosticsProvider()
    config = RuntimeConfig(metadata_validation=[{"identifier": "author", "required": True}])

    # meta=None is not a list — branch 302->309 is taken
    rule_meta_none = SimpleNamespace(name="r", meta=None, location=None)
    ast_obj = cast(YaraFile, SimpleNamespace(rules=[rule_meta_none]))
    diags = provider._validate_metadata(ast_obj, config)
    assert len(diags) == 1
    assert "missing required metadata 'author'" in diags[0].message

    # meta=42 is not a list — same branch
    rule_meta_int = SimpleNamespace(name="r", meta=42, location=None)
    ast_obj2 = cast(YaraFile, SimpleNamespace(rules=[rule_meta_int]))
    diags2 = provider._validate_metadata(ast_obj2, config)
    assert len(diags2) == 1


# ---------------------------------------------------------------------------
# Line 306->303 — meta entry whose key is None (skipped in lookup)
# ---------------------------------------------------------------------------


def test_validate_metadata_entry_with_null_key_is_skipped() -> None:
    """
    Purpose: cover branch 306->303 (if key is not None: is False, loop continues).

    An entry in the meta list where both 'key' and 'identifier' attributes
    are absent (so getattr returns None for both) must be silently skipped.
    The rule is still evaluated for the 'required' check and produces a
    missing-metadata diagnostic because the entry was not added to meta_dict.
    """
    provider = DiagnosticsProvider()
    config = RuntimeConfig(metadata_validation=[{"identifier": "author", "required": True}])

    # Entry with no key/identifier → key is None → if key is not None skipped
    entry_null_key = SimpleNamespace()  # no 'key', no 'identifier' attrs
    rule = SimpleNamespace(name="r", meta=[entry_null_key], location=None)
    ast_obj = cast(YaraFile, SimpleNamespace(rules=[rule]))
    diags = provider._validate_metadata(ast_obj, config)
    # Entry was not counted → 'author' still missing
    assert len(diags) == 1
    assert "missing required metadata 'author'" in diags[0].message
