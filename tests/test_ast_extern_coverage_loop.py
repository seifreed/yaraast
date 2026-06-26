# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in yaraast/ast/extern.py.

Each test corresponds directly to a production code path identified by
coverage analysis.  All tests execute real class constructors, methods,
and module-level helpers.  No mocks, stubs, or fake implementations are
used anywhere in this file.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.extern import (
    ExternImport,
    ExternNamespace,
    ExternRule,
    ExternRuleReference,
    _normalize_string_list,
    _validate_quoted_field_text,
    _validate_rule_identifiers,
    _validate_yara_identifier,
    _validate_yara_identifier_path,
)
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH

# ---------------------------------------------------------------------------
# _validate_yara_identifier (lines 28-39)
# ---------------------------------------------------------------------------


def test_validate_yara_identifier_raises_type_error_for_non_string() -> None:
    """Line 30-31: non-string input raises TypeError."""
    with pytest.raises(TypeError, match="Extern rule identifier must be a string"):
        _validate_yara_identifier(123, "extern rule")


def test_validate_yara_identifier_raises_value_error_for_keyword() -> None:
    """Line 38-39: a YARA reserved keyword raises ValueError."""
    keyword = next(iter(KEYWORDS))
    with pytest.raises(ValueError, match=f"Invalid extern rule identifier '{keyword}'"):
        _validate_yara_identifier(keyword, "extern rule")


def test_validate_yara_identifier_raises_value_error_for_bad_pattern() -> None:
    """Line 38-39: identifiers starting with a digit are invalid."""
    with pytest.raises(ValueError, match="Invalid extern rule identifier '123abc'"):
        _validate_yara_identifier("123abc", "extern rule")


def test_validate_yara_identifier_raises_value_error_for_overlong_name() -> None:
    """Line 38-39: identifiers exceeding YARA_IDENTIFIER_MAX_LENGTH are invalid."""
    overlong = "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)
    with pytest.raises(ValueError, match="Invalid extern rule identifier"):
        _validate_yara_identifier(overlong, "extern rule")


def test_validate_yara_identifier_accepts_valid_name() -> None:
    """Sanity check: valid identifier is returned unchanged."""
    result = _validate_yara_identifier("valid_name", "extern rule")
    assert result == "valid_name"


# ---------------------------------------------------------------------------
# _validate_quoted_field_text (lines 42-45)
# ---------------------------------------------------------------------------


def test_validate_quoted_field_text_raises_for_double_quote() -> None:
    """Line 44-45: a double-quote character in value raises ValueError."""
    with pytest.raises(ValueError, match="must not contain quotes or control characters"):
        _validate_quoted_field_text('has"quote', "ExternImport module_path")


def test_validate_quoted_field_text_raises_for_control_char_below_0x20() -> None:
    """Line 44-45: ASCII control character below 0x20 raises ValueError."""
    with pytest.raises(ValueError, match="must not contain quotes or control characters"):
        _validate_quoted_field_text("has\x01ctrl", "ExternImport module_path")


def test_validate_quoted_field_text_raises_for_delete_char_0x7f() -> None:
    """Line 44-45: DEL character (0x7F) raises ValueError."""
    with pytest.raises(ValueError, match="must not contain quotes or control characters"):
        _validate_quoted_field_text("has\x7fdelete", "ExternImport module_path")


def test_validate_quoted_field_text_accepts_clean_string() -> None:
    """Sanity check: a clean path value returns without error."""
    _validate_quoted_field_text("clean/path/module", "ExternImport module_path")


# ---------------------------------------------------------------------------
# _validate_yara_identifier_path (lines 48-58)
# ---------------------------------------------------------------------------


def test_validate_yara_identifier_path_raises_type_error_for_non_string() -> None:
    """Line 50-51: non-string path raises TypeError."""
    with pytest.raises(TypeError, match="Namespace identifier must be a string"):
        _validate_yara_identifier_path(123, "namespace")


def test_validate_yara_identifier_path_raises_value_error_for_empty_segment() -> None:
    """Line 54-55: a path with an empty segment (double dot) raises ValueError."""
    with pytest.raises(ValueError, match=r"Invalid namespace identifier 'ns\.\.rule'"):
        _validate_yara_identifier_path("ns..rule", "namespace")


def test_validate_yara_identifier_path_accepts_dotted_path() -> None:
    """Sanity check: a valid dotted path is returned unchanged."""
    result = _validate_yara_identifier_path("my_ns.my_rule", "namespace")
    assert result == "my_ns.my_rule"


# ---------------------------------------------------------------------------
# _normalize_string_list (lines 61-70)
# ---------------------------------------------------------------------------


def test_normalize_string_list_raises_type_error_for_non_list() -> None:
    """Line 63: passing a non-list raises TypeError."""
    with pytest.raises(TypeError, match="rules must be a list of strings"):
        _normalize_string_list(cast(Any, "not_a_list"), "rules")


def test_normalize_string_list_raises_type_error_for_list_with_non_string_item() -> None:
    """Line 63: a list containing a non-string element raises TypeError."""
    with pytest.raises(TypeError, match="rules must be a list of strings"):
        _normalize_string_list(cast(Any, ["valid", 123]), "rules")


def test_normalize_string_list_raises_value_error_for_blank_item() -> None:
    """Line 67-69: a list with a blank string raises ValueError."""
    with pytest.raises(ValueError, match="rules must contain non-empty strings"):
        _normalize_string_list(["valid", "  "], "rules")


def test_normalize_string_list_returns_empty_list_for_none() -> None:
    """Line 62-63: None input returns empty list."""
    result = _normalize_string_list(None, "rules")
    assert result == []


def test_normalize_string_list_returns_copy_of_valid_list() -> None:
    """Line 70: valid list is returned as a new list."""
    source = ["RuleA", "RuleB"]
    result = _normalize_string_list(source, "rules")
    assert result == source
    assert result is not source


# ---------------------------------------------------------------------------
# _validate_rule_identifiers (lines 73-75)
# ---------------------------------------------------------------------------


def test_validate_rule_identifiers_accepts_simple_names() -> None:
    """Line 74-75: iterates over valid identifiers without raising."""
    _validate_rule_identifiers(["RuleA", "RuleB"], "extern rule")


def test_validate_rule_identifiers_accepts_dotted_paths() -> None:
    """Line 74-75: iterates over valid dotted paths without raising."""
    _validate_rule_identifiers(["ns.RuleA", "other_ns.RuleB"], "extern rule")


def test_validate_rule_identifiers_raises_on_invalid_identifier() -> None:
    """Line 74-75: raises ValueError when any identifier is invalid."""
    with pytest.raises(ValueError, match="Invalid extern rule identifier"):
        _validate_rule_identifiers(["valid_rule", "123invalid"], "extern rule")


# ---------------------------------------------------------------------------
# _normalize_extern_rule_modifiers - lines 98-103 (unknown-modifier path)
# ---------------------------------------------------------------------------


def test_normalize_extern_rule_modifiers_unknown_identifier_raises_value_error() -> None:
    """Lines 98-103: a valid identifier that is not a known modifier type raises ValueError.

    The string 'xyz' passes require_rule_modifier_identifier (it is a valid
    YARA identifier) but fails RuleModifierType.from_string, which triggers
    the ValueError on line 101-102.
    """
    rule = ExternRule(name="MyRule", modifiers=cast(Any, ["xyz"]))
    with pytest.raises(ValueError, match="Invalid rule modifier 'xyz'"):
        _ = rule.is_private


# ---------------------------------------------------------------------------
# ExternRuleReference.validate_structure (lines 172->exit, 174)
# ---------------------------------------------------------------------------


def test_extern_rule_reference_validate_structure_with_namespace_covers_branch() -> None:
    """Lines 172->exit and 174: validate_structure exercises the namespace branch."""
    ref = ExternRuleReference(rule_name="MyRule", namespace="my_ns")
    ref.validate_structure()
    assert ref.qualified_name == "my_ns.MyRule"


def test_extern_rule_reference_validate_structure_without_namespace() -> None:
    """Covers the no-namespace branch (namespace is None) for completeness."""
    ref = ExternRuleReference(rule_name="MyRule")
    ref.validate_structure()
    assert ref.qualified_name == "MyRule"


# ---------------------------------------------------------------------------
# ExternImport.validate_structure - alias path (line 216) and rules path (line 218)
# ---------------------------------------------------------------------------


def test_extern_import_validate_structure_with_alias_covers_line_216() -> None:
    """Line 216: validate_structure calls _validate_yara_identifier on the alias."""
    imp = ExternImport(module_path="mymodule", alias="my_alias")
    imp.validate_structure()
    assert imp.alias == "my_alias"


def test_extern_import_validate_structure_with_invalid_alias_raises() -> None:
    """Line 216: an alias that is a YARA keyword raises ValueError."""
    keyword = next(kw for kw in KEYWORDS if kw.isidentifier())
    imp = ExternImport(module_path="mymodule", alias=keyword)
    with pytest.raises(ValueError, match=f"Invalid import alias identifier '{keyword}'"):
        imp.validate_structure()


def test_extern_import_validate_structure_with_rules_covers_line_218() -> None:
    """Line 218: validate_structure calls _validate_rule_identifiers on rules list."""
    imp = ExternImport(module_path="mymodule", rules=["RuleA", "ns.RuleB"])
    imp.validate_structure()
    assert imp.rules == ["RuleA", "ns.RuleB"]


def test_extern_import_validate_structure_with_invalid_rule_name_raises() -> None:
    """Line 218: an invalid identifier in rules raises ValueError."""
    imp = ExternImport(module_path="mymodule", rules=["123bad"])
    with pytest.raises(ValueError, match="Invalid extern rule identifier"):
        imp.validate_structure()


# ---------------------------------------------------------------------------
# ExternNamespace.validate_structure (lines 259-261)
# ---------------------------------------------------------------------------


def test_extern_namespace_validate_structure_plain() -> None:
    """Lines 259-261: validate_structure succeeds on a namespace with no rules."""
    ns = ExternNamespace(name="my_namespace")
    ns.validate_structure()
    assert ns.name == "my_namespace"


def test_extern_namespace_validate_structure_with_rules() -> None:
    """Lines 259-261: validate_structure succeeds and validates contained rules."""
    rule = ExternRule(name="DetectMalware")
    ns = ExternNamespace(name="ext", extern_rules=[rule])
    ns.validate_structure()
    assert len(ns.extern_rules) == 1


def test_extern_namespace_validate_structure_raises_for_invalid_name() -> None:
    """Lines 259-260: validate_structure raises when name is not a valid string."""
    ns = ExternNamespace(name=cast(Any, 42))
    with pytest.raises(TypeError, match="ExternNamespace name must be a string"):
        ns.validate_structure()


def test_extern_namespace_validate_structure_raises_for_keyword_name() -> None:
    """Lines 259-261: validate_structure raises when name is a YARA keyword."""
    keyword = next(kw for kw in KEYWORDS if kw.isidentifier())
    ns = ExternNamespace(name=keyword)
    with pytest.raises(ValueError, match=f"Invalid namespace identifier '{keyword}'"):
        ns.validate_structure()


# ---------------------------------------------------------------------------
# ExternNamespace.__str__ (line 297-299)
# ---------------------------------------------------------------------------


def test_extern_namespace_str_returns_formatted_name() -> None:
    """__str__ on ExternNamespace returns 'namespace <name>'."""
    ns = ExternNamespace(name="my_namespace")
    assert str(ns) == "namespace my_namespace"


def test_extern_namespace_str_with_rules_still_returns_name_only() -> None:
    """__str__ is independent of contained extern rules."""
    ns = ExternNamespace(name="ext", extern_rules=[ExternRule(name="DetectMalware")])
    assert str(ns) == "namespace ext"


def test_extern_namespace_str_raises_for_invalid_name() -> None:
    """__str__ raises when name is not a valid string."""
    ns = ExternNamespace(name=cast(Any, 42))
    with pytest.raises(TypeError, match="ExternNamespace name must be a string"):
        str(ns)
