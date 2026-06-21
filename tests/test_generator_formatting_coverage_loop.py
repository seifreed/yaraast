# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for yaraast/codegen/generator_formatting.py.

Each test function exercises a distinct slice of the module's logic through
direct calls to the public (and private-but-reachable) functions.  No mocks,
stubs, or test doubles of the module under test are used.  Where a helper
type is needed (e.g. a namespace-like object), Python's ``SimpleNamespace``
or real AST node classes are used so that actual production code paths run.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from yaraast.ast.modifiers import RuleModifier, RuleModifierType
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaType
from yaraast.ast.rules import Tag
from yaraast.codegen.generator_formatting import (
    _YARA_META_INTEGER_MIN,
    _rule_modifier_name,
    contextual_local_identifier_names,
    contextual_local_identifiers,
    format_boolean_literal,
    format_hex_jump,
    format_import_alias,
    format_meta_key,
    format_meta_literal,
    format_nonempty_quoted_value,
    format_regex_literal,
    format_rule_modifiers,
    format_rule_tags,
    format_yarax_local_identifier,
    reject_import_alias,
    validate_extern_rule_identifiers,
    validate_optional_namespace,
    validate_rule_collections,
    validate_rule_identifiers,
    validate_rule_meta,
    validate_rule_tag_name,
    validate_rule_tags,
    validate_yara_expression_identifier,
    validate_yara_file_collections,
    validate_yara_identifier,
    validate_yara_identifier_path,
)
from yaraast.lexer.lexer_tables import YARA_IDENTIFIER_MAX_LENGTH

# ---------------------------------------------------------------------------
# format_rule_modifiers
# ---------------------------------------------------------------------------


def test_format_rule_modifiers_returns_empty_for_none() -> None:
    """Line 50: None input must return empty string without error."""
    assert format_rule_modifiers(None) == ""


def test_format_rule_modifiers_raises_for_non_collection() -> None:
    """Lines 52-53: non-list/tuple must raise TypeError."""
    bad_values: list[Any] = ["private", 123, False]
    for bad in bad_values:
        with pytest.raises(TypeError, match="Rule modifiers must be a list or tuple"):
            format_rule_modifiers(bad)


def test_format_rule_modifiers_raises_for_invalid_modifier_string() -> None:
    """Lines 65-66: an unknown modifier string must raise ValueError."""
    with pytest.raises(ValueError, match="Invalid rule modifier 'bad_modifier'"):
        format_rule_modifiers(["bad_modifier"])


def test_rule_modifier_name_with_rule_modifier_node() -> None:
    """Line 71: RuleModifier AST node must produce its string value."""
    result = _rule_modifier_name(RuleModifier(RuleModifierType.GLOBAL))
    assert result == "global"


def test_rule_modifier_name_raises_for_unknown_type() -> None:
    """Lines 74-75: unknown object type must raise TypeError."""
    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        _rule_modifier_name(SimpleNamespace())


# ---------------------------------------------------------------------------
# validate_rule_identifiers
# ---------------------------------------------------------------------------


def test_validate_rule_identifiers_passes_for_empty_list() -> None:
    """Line 80: empty list must return immediately without error."""
    validate_rule_identifiers([])


def test_validate_rule_identifiers_raises_for_duplicates() -> None:
    """Lines 86-87: duplicate rule name must raise ValueError."""
    rules = [SimpleNamespace(name="foo"), SimpleNamespace(name="foo")]
    with pytest.raises(ValueError, match="Duplicate rule identifier 'foo'"):
        validate_rule_identifiers(rules)


# ---------------------------------------------------------------------------
# validate_extern_rule_identifiers and _validate_extern_rule_identifier
# ---------------------------------------------------------------------------


def test_validate_extern_rule_identifiers_extern_no_namespace() -> None:
    """Line 100: flat extern_rules list with no namespace must be processed."""
    validate_extern_rule_identifiers(
        [],
        [SimpleNamespace(name="foo", namespace=None)],
        [],
    )


def test_validate_extern_rule_identifiers_namespace_loop() -> None:
    """Lines 103-108: namespace containing extern_rules must be iterated."""
    ns = SimpleNamespace(
        name="myns",
        extern_rules=[SimpleNamespace(name="bar", namespace=None)],
    )
    validate_extern_rule_identifiers([], [], [ns])


def test_validate_extern_rule_identifiers_skips_non_collection_extern_rules() -> None:
    """Lines 105-106: namespace whose extern_rules is not list/tuple must be skipped."""
    ns = SimpleNamespace(name="myns", extern_rules="not_a_list")
    validate_extern_rule_identifiers([], [], [ns])


def test_validate_extern_rule_identifier_duplicate_conflicts_with_rule() -> None:
    """Lines 129-130: extern rule whose name matches a local rule must raise ValueError."""
    rules = [SimpleNamespace(name="foo")]
    extern_rules = [SimpleNamespace(name="foo", namespace=None)]
    with pytest.raises(ValueError, match="Duplicate rule identifier 'foo'"):
        validate_extern_rule_identifiers(rules, extern_rules, [])


def test_validate_extern_rule_identifier_duplicate_qualified_name() -> None:
    """Lines 134-136: a second extern rule with the same (namespace, name) key must raise ValueError.

    The qualified form 'ns.name' appears in the error message when namespace is set.
    """
    extern_rules = [
        SimpleNamespace(name="bar", namespace="myns"),
        SimpleNamespace(name="bar", namespace="myns"),
    ]
    with pytest.raises(ValueError, match=r"Duplicate extern rule identifier 'myns\.bar'"):
        validate_extern_rule_identifiers([], extern_rules, [])


def test_validate_extern_rule_identifier_duplicate_unqualified_name() -> None:
    """Lines 134-136: a second extern rule without namespace also raises ValueError."""
    ns = SimpleNamespace(
        name="myns",
        extern_rules=[
            SimpleNamespace(name="bar", namespace=None),
            SimpleNamespace(name="bar", namespace=None),
        ],
    )
    with pytest.raises(ValueError, match=r"Duplicate extern rule identifier 'myns\.bar'"):
        validate_extern_rule_identifiers([], [], [ns])


# ---------------------------------------------------------------------------
# validate_yara_file_collections
# ---------------------------------------------------------------------------


def test_validate_yara_file_collections_raises_when_field_is_not_collection() -> None:
    """Lines 145-146: a scalar field on the file node must raise TypeError."""

    class BadFile:
        imports = "not_a_list"
        includes: list[Any] = []
        rules: list[Any] = []
        extern_rules: list[Any] = []
        extern_imports: list[Any] = []
        pragmas: list[Any] = []
        namespaces: list[Any] = []

    with pytest.raises(TypeError, match="YaraFile imports must be a list or tuple"):
        validate_yara_file_collections(BadFile())


# ---------------------------------------------------------------------------
# validate_rule_collections
# ---------------------------------------------------------------------------


def test_validate_rule_collections_raises_for_non_list_tags() -> None:
    """Lines 153-154: tags not being list/tuple must raise TypeError."""

    class BadRule:
        tags = "not_a_list"
        pragmas: list[Any] = []

    with pytest.raises(TypeError, match="Rule tags must be a list or tuple"):
        validate_rule_collections(BadRule())


def test_validate_rule_collections_raises_for_non_pragma_item() -> None:
    """Lines 157-159: pragma list containing a non-InRulePragma must raise TypeError."""

    class RuleWithBadPragma:
        tags: list[Any] = []
        pragmas = [SimpleNamespace()]

    with pytest.raises(TypeError, match="Rule pragmas must contain InRulePragma nodes"):
        validate_rule_collections(RuleWithBadPragma())


def test_validate_rule_collections_accepts_valid_in_rule_pragma() -> None:
    """Lines 155-159: a real InRulePragma instance must pass validation."""
    pragma = Pragma(PragmaType.INCLUDE_ONCE, "myfile.yar")
    in_rule_pragma = InRulePragma(pragma)

    class GoodRule:
        tags: list[Any] = []
        pragmas = [in_rule_pragma]

    validate_rule_collections(GoodRule())


# ---------------------------------------------------------------------------
# format_rule_tags
# ---------------------------------------------------------------------------


def test_format_rule_tags_returns_empty_for_none() -> None:
    """Line 164: None tags must return empty string."""
    assert format_rule_tags(None) == ""


def test_format_rule_tags_raises_for_non_collection() -> None:
    """Lines 166-167: non-list/tuple must raise TypeError."""
    bad_values: list[Any] = ["t1", 123, False]
    for bad in bad_values:
        with pytest.raises(TypeError, match="Rule tags must be a list or tuple"):
            format_rule_tags(bad)


# ---------------------------------------------------------------------------
# validate_rule_tags
# ---------------------------------------------------------------------------


def test_validate_rule_tags_passes_for_empty_list() -> None:
    """Line 177: empty list must return immediately without error."""
    validate_rule_tags([])


def test_validate_rule_tags_raises_for_duplicate() -> None:
    """Lines 184-185: duplicate tag must raise ValueError."""
    with pytest.raises(ValueError, match="Duplicate tag identifier 't1'"):
        validate_rule_tags(["t1", "t1"])


# ---------------------------------------------------------------------------
# validate_rule_meta
# ---------------------------------------------------------------------------


def test_validate_rule_meta_passes_for_none() -> None:
    """Line 191: None meta must pass without error."""
    validate_rule_meta(None)


def test_validate_rule_meta_raises_for_invalid_type() -> None:
    """Lines 193-194: integer meta must raise TypeError."""
    with pytest.raises(TypeError, match="Rule meta must be a dictionary, list, or tuple"):
        validate_rule_meta(42)


def test_validate_rule_meta_passes_for_dict() -> None:
    """Lines 196-198: dict meta must validate each entry without error."""
    validate_rule_meta({"author": "me", "version": 1})


def test_validate_rule_meta_raises_for_list_entry_without_key_value() -> None:
    """Lines 201-202: list entry lacking key/value attributes must raise TypeError."""
    with pytest.raises(TypeError, match="Rule meta must contain meta entries"):
        validate_rule_meta([SimpleNamespace()])


def test_validate_rule_meta_passes_for_list_of_meta_entries() -> None:
    """Line 203: list of valid entries with key/value/scope must pass."""
    entry = SimpleNamespace(key="author", value="me", scope=None)
    validate_rule_meta([entry])


# ---------------------------------------------------------------------------
# validate_rule_tag_name
# ---------------------------------------------------------------------------


def test_validate_rule_tag_name_raises_for_tag_with_non_string_name() -> None:
    """Lines 213-214: Tag node with non-str name must raise TypeError."""
    bad_name: Any = 123
    with pytest.raises(TypeError, match="Tag name must be a string"):
        validate_rule_tag_name(Tag(name=bad_name))


def test_validate_rule_tag_name_accepts_duck_typed_name_object() -> None:
    """Lines 209-212: an object with a string 'name' attribute (not ASTNode) must succeed."""

    class NamedThing:
        name = "valid_tag"

    assert validate_rule_tag_name(NamedThing()) == "valid_tag"


def test_validate_rule_tag_name_raises_for_unrecognised_object() -> None:
    """Lines 215-216: object with no 'name' attribute and not a Tag must raise TypeError."""
    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        validate_rule_tag_name(SimpleNamespace())


# ---------------------------------------------------------------------------
# validate_yara_identifier
# ---------------------------------------------------------------------------


def test_validate_yara_identifier_raises_for_non_string() -> None:
    """Lines 221-222: non-string name must raise TypeError."""
    bad_values: list[Any] = [42, None, True, []]
    for bad in bad_values:
        with pytest.raises(TypeError, match="identifier must be a string"):
            validate_yara_identifier(bad, "rule")


def test_validate_yara_identifier_raises_for_invalid_pattern() -> None:
    """Lines 233-234: name starting with digit must raise ValueError."""
    with pytest.raises(ValueError, match="Invalid rule identifier '123bad'"):
        validate_yara_identifier("123bad", "rule")


def test_validate_yara_identifier_raises_for_keyword() -> None:
    """Lines 233-234: YARA keyword as non-contextual identifier must raise ValueError."""
    with pytest.raises(ValueError, match="Invalid rule identifier 'rule'"):
        validate_yara_identifier("rule", "rule")


def test_validate_yara_identifier_raises_for_too_long_name() -> None:
    """Lines 233-234: name exceeding YARA_IDENTIFIER_MAX_LENGTH must raise ValueError."""
    long_name = "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        validate_yara_identifier(long_name, "rule")


# ---------------------------------------------------------------------------
# contextual_local_identifier_names
# ---------------------------------------------------------------------------


def test_contextual_local_identifier_names_filters_non_strings_and_dollar_names() -> None:
    """Line 256: non-string and dollar-prefixed names must be excluded from result."""
    result = contextual_local_identifier_names("foo", 42, None, "$bar", "baz")
    assert result == frozenset({"foo", "baz"})


# ---------------------------------------------------------------------------
# validate_yara_expression_identifier
# ---------------------------------------------------------------------------


def test_validate_yara_expression_identifier_raises_for_non_string() -> None:
    """Lines 267-268: non-string input must raise TypeError."""
    bad_values: list[Any] = [42, None, True]
    for bad in bad_values:
        with pytest.raises(TypeError, match="Identifier must be a string"):
            validate_yara_expression_identifier(bad)


def test_validate_yara_expression_identifier_raises_for_dollar_prefix() -> None:
    """Lines 270-271: string starting with '$' must raise ValueError."""
    with pytest.raises(ValueError, match="String references must use StringIdentifier"):
        validate_yara_expression_identifier("$myvar")


def test_validate_yara_expression_identifier_accepts_contextual_keyword() -> None:
    """Line 279: 'as' in contextual_locals must be returned without error."""
    result = validate_yara_expression_identifier("as", frozenset({"as"}))
    assert result == "as"


# ---------------------------------------------------------------------------
# validate_yara_identifier_path
# ---------------------------------------------------------------------------


def test_validate_yara_identifier_path_raises_for_non_string() -> None:
    """Lines 285-286: non-string path must raise TypeError."""
    bad_values: list[Any] = [42, None, True]
    for bad in bad_values:
        with pytest.raises(TypeError, match="identifier must be a string"):
            validate_yara_identifier_path(bad, "namespace")


def test_validate_yara_identifier_path_raises_for_empty_segment() -> None:
    """Lines 289-290: path with an empty segment (double dot) must raise ValueError."""
    with pytest.raises(ValueError, match=r"Invalid namespace identifier 'foo\.\.bar'"):
        validate_yara_identifier_path("foo..bar", "namespace")


def test_validate_yara_identifier_path_raises_for_leading_dot() -> None:
    """Lines 289-290: path starting with '.' produces an empty first segment."""
    with pytest.raises(ValueError, match="Invalid namespace identifier"):
        validate_yara_identifier_path(".foo", "namespace")


# ---------------------------------------------------------------------------
# validate_optional_namespace
# ---------------------------------------------------------------------------


def test_validate_optional_namespace_returns_default_when_none() -> None:
    """Lines 299-300: None namespace must return the default_namespace argument."""
    assert validate_optional_namespace(None, None) is None
    assert validate_optional_namespace(None, "myns") == "myns"


def test_validate_optional_namespace_raises_for_non_string() -> None:
    """Lines 301-303: non-string namespace must raise TypeError."""
    bad_values: list[Any] = [42, True, []]
    for bad in bad_values:
        with pytest.raises(TypeError, match="Namespace must be a string"):
            validate_optional_namespace(bad)


def test_validate_optional_namespace_validates_string_path() -> None:
    """Line 304: valid string namespace must be returned as-is."""
    assert validate_optional_namespace("myns") == "myns"


# ---------------------------------------------------------------------------
# format_meta_key
# ---------------------------------------------------------------------------


def test_format_meta_key_raises_for_unsupported_scope() -> None:
    """Lines 311-312: scope with value 'private' must raise ValueError."""
    scope = SimpleNamespace(value="private")
    with pytest.raises(ValueError, match="Unsupported meta scope 'private'"):
        format_meta_key("author", scope)


# ---------------------------------------------------------------------------
# format_meta_literal
# ---------------------------------------------------------------------------


def test_format_meta_literal_preserve_quoted_returns_value_unchanged() -> None:
    """Line 319: already-quoted string with preserve_quoted=True must pass through."""
    result = format_meta_literal('"already quoted"', preserve_quoted=True)
    assert result == '"already quoted"'


def test_format_meta_literal_str_without_preserve_quoted_wraps_in_quotes() -> None:
    """Line 322: string with preserve_quoted=False must be wrapped in double quotes."""
    result = format_meta_literal("hello", preserve_quoted=False)
    assert result == '"hello"'


def test_format_meta_literal_bool_true_value() -> None:
    """Lines 325-326: True must produce the string 'true'."""
    assert format_meta_literal(True) == "true"


def test_format_meta_literal_bool_false_value() -> None:
    """Lines 328-329: False must produce the string 'false'."""
    assert format_meta_literal(False) == "false"


def test_format_meta_literal_integer_at_minimum_raises() -> None:
    """Lines 325-326 (branch): _YARA_META_INTEGER_MIN triggers the out-of-range error."""
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        format_meta_literal(_YARA_META_INTEGER_MIN)


# ---------------------------------------------------------------------------
# format_nonempty_quoted_value
# ---------------------------------------------------------------------------


def test_format_nonempty_quoted_value_raises_for_non_string() -> None:
    """Lines 343-344: non-string input must raise TypeError."""
    bad_values: list[Any] = [42, None, True]
    for bad in bad_values:
        with pytest.raises(TypeError, match="must be a string for libyara output"):
            format_nonempty_quoted_value(bad, "Import")


def test_format_nonempty_quoted_value_raises_for_blank_string() -> None:
    """Lines 346-347: whitespace-only string must raise ValueError."""
    with pytest.raises(ValueError, match="must not be empty for libyara output"):
        format_nonempty_quoted_value("   ", "Import")


def test_format_nonempty_quoted_value_raises_for_embedded_quote() -> None:
    """Lines 349-350: string containing a double-quote character must raise ValueError."""
    with pytest.raises(ValueError, match="must not contain quotes or control characters"):
        format_nonempty_quoted_value('hello"world', "Import")


def test_format_nonempty_quoted_value_raises_for_control_character() -> None:
    """Lines 349-350: string containing a control character (0x01) must raise ValueError."""
    with pytest.raises(ValueError, match="must not contain quotes or control characters"):
        format_nonempty_quoted_value("hello\x01world", "Import")


def test_format_nonempty_quoted_value_raises_for_del_character() -> None:
    """Lines 349-350: string containing DEL (0x7F) must raise ValueError."""
    with pytest.raises(ValueError, match="must not contain quotes or control characters"):
        format_nonempty_quoted_value("hello\x7fworld", "Import")


# ---------------------------------------------------------------------------
# reject_import_alias
# ---------------------------------------------------------------------------


def test_reject_import_alias_accepts_none() -> None:
    """Line 357: None alias must return without error."""
    reject_import_alias(None)


def test_reject_import_alias_raises_for_non_string() -> None:
    """Lines 358-360: non-string alias must raise TypeError."""
    bad_values: list[Any] = [42, True, []]
    for bad in bad_values:
        with pytest.raises(TypeError, match="Import alias must be a string"):
            reject_import_alias(bad)


def test_reject_import_alias_raises_for_any_string() -> None:
    """Line 361: any string alias must raise ValueError."""
    with pytest.raises(ValueError, match="Import aliases are not supported"):
        reject_import_alias("myalias")


# ---------------------------------------------------------------------------
# format_import_alias
# ---------------------------------------------------------------------------


def test_format_import_alias_returns_empty_for_none() -> None:
    """Line 365: None alias must return empty string."""
    assert format_import_alias(None) == ""


def test_format_import_alias_raises_for_non_string() -> None:
    """Lines 367-369: non-string alias must raise TypeError."""
    bad_values: list[Any] = [42, True, []]
    for bad in bad_values:
        with pytest.raises(TypeError, match="Import alias must be a string"):
            format_import_alias(bad)


def test_format_import_alias_returns_formatted_alias() -> None:
    """Line 370: valid string alias must be formatted as ' as <name>'."""
    assert format_import_alias("myalias") == " as myalias"


# ---------------------------------------------------------------------------
# format_regex_literal
# ---------------------------------------------------------------------------


def test_format_regex_literal_produces_slash_delimited_output() -> None:
    """Lines 374-376: valid pattern and modifiers must be wrapped in slashes."""
    assert format_regex_literal("a.b", "i") == "/a.b/i"
    assert format_regex_literal("abc", "") == "/abc/"


# ---------------------------------------------------------------------------
# format_boolean_literal
# ---------------------------------------------------------------------------


def test_format_boolean_literal_raises_for_non_boolean() -> None:
    """Lines 381-382: non-bool input must raise TypeError."""
    bad_values: list[Any] = [1, 0, "true", None]
    for bad in bad_values:
        with pytest.raises(TypeError, match="Boolean literal value must be a boolean"):
            format_boolean_literal(bad)


# ---------------------------------------------------------------------------
# format_hex_jump
# ---------------------------------------------------------------------------


def test_format_hex_jump_delegates_to_format_hex_jump_bounds() -> None:
    """Line 387: format_hex_jump must produce correct output for representative inputs."""
    assert format_hex_jump(1, 5) == "[1-5]"
    assert format_hex_jump(None, None) == "[-]"
    assert format_hex_jump(3, 3) == "[3]"


# ---------------------------------------------------------------------------
# contextual_local_identifiers context manager
# ---------------------------------------------------------------------------


def test_contextual_local_identifiers_pushes_and_restores_locals() -> None:
    """Lines 246-251: context manager must push locals onto generator and restore on exit."""

    class FakeGenerator:
        _contextual_local_identifiers: tuple[frozenset[str], ...]

    gen = FakeGenerator()
    local_set = frozenset({"x", "y"})

    with contextual_local_identifiers(gen, local_set):
        assert gen._contextual_local_identifiers == (local_set,)

    assert gen._contextual_local_identifiers == ()


def test_contextual_local_identifiers_is_nestable() -> None:
    """Lines 246-251: nested context managers must stack and unstack correctly."""

    class FakeGenerator:
        _contextual_local_identifiers: tuple[frozenset[str], ...]

    gen = FakeGenerator()
    outer = frozenset({"a"})
    inner = frozenset({"b"})

    with contextual_local_identifiers(gen, outer):
        assert gen._contextual_local_identifiers == (outer,)
        with contextual_local_identifiers(gen, inner):
            assert gen._contextual_local_identifiers == (outer, inner)
        assert gen._contextual_local_identifiers == (outer,)

    assert gen._contextual_local_identifiers == ()


# ---------------------------------------------------------------------------
# format_yarax_local_identifier
# ---------------------------------------------------------------------------


def test_format_yarax_local_identifier_raises_for_non_string() -> None:
    """Lines 255-256: non-string identifier must delegate to validate_yara_identifier."""
    bad_values: list[Any] = [42, None, True]
    for bad in bad_values:
        with pytest.raises(TypeError, match="identifier must be a string"):
            format_yarax_local_identifier(bad, "field")


def test_format_yarax_local_identifier_accepts_dollar_prefixed_string() -> None:
    """Lines 257-258: '$'-prefixed string must pass through string reference validation."""
    result = format_yarax_local_identifier("$myvar", "field")
    assert result == "$myvar"


def test_format_yarax_local_identifier_validates_plain_name() -> None:
    """Line 259: plain identifier must pass validate_yara_identifier and be returned."""
    assert format_yarax_local_identifier("myvar", "field") == "myvar"


# ---------------------------------------------------------------------------
# Success-path (happy-path) branches not exercised by error-path tests above
# ---------------------------------------------------------------------------


def test_format_rule_modifiers_empty_list_returns_empty() -> None:
    """Line 55: empty list of modifiers must return empty string."""
    assert format_rule_modifiers([]) == ""


def test_format_rule_modifiers_valid_list_returns_joined() -> None:
    """Line 57: valid list of modifier strings must be space-joined and returned."""
    result = format_rule_modifiers(["private", "global"])
    assert result == "private global"


def test_validate_rule_modifiers_continues_for_valid_modifier() -> None:
    """Lines 61-64: each valid modifier in the list must be accepted without raising."""
    from yaraast.codegen.generator_formatting import validate_rule_modifiers

    validate_rule_modifiers(["global", "private"])


def test_validate_rule_identifiers_accepts_non_duplicate_rules() -> None:
    """Lines 83-88: distinct rule names must all be accepted without error."""
    validate_rule_identifiers([SimpleNamespace(name="rule_a"), SimpleNamespace(name="rule_b")])


def test_validate_yara_file_collections_passes_all_list_fields() -> None:
    """Lines 141-144: all-list fields must trigger the continue branch for every field."""

    class GoodFile:
        imports: list[Any] = []
        includes: list[Any] = []
        rules: list[Any] = []
        extern_rules: list[Any] = []
        extern_imports: list[Any] = []
        pragmas: list[Any] = []
        namespaces: list[Any] = []

    validate_yara_file_collections(GoodFile())


def test_format_rule_tags_empty_list_returns_empty() -> None:
    """Lines 168-169: empty list of tags must return empty string."""
    assert format_rule_tags([]) == ""


def test_format_rule_tags_valid_list_returns_joined() -> None:
    """Lines 170-172: valid list of tag strings must be space-joined and returned."""
    result = format_rule_tags(["alpha", "beta"])
    assert result == "alpha beta"


def test_validate_rule_tags_accepts_valid_tags() -> None:
    """Lines 180-186: distinct tag names must all be accepted without error."""
    validate_rule_tags(["first", "second", "third"])


def test_validate_yara_expression_identifier_returns_expression_keyword() -> None:
    """Line 273: expression keyword like 'filesize' must be returned immediately."""
    for keyword in ("filesize", "entrypoint", "true", "false"):
        assert validate_yara_expression_identifier(keyword) == keyword


def test_validate_yara_expression_identifier_returns_plain_identifier() -> None:
    """Line 280: valid plain identifier must delegate to validate_yara_identifier and return."""
    result = validate_yara_expression_identifier("myidentifier")
    assert result == "myidentifier"


def test_format_meta_literal_integer_returns_formatted() -> None:
    """Lines 328 (int branch success path): valid int must produce formatted output."""
    assert format_meta_literal(42) == "42"
    assert format_meta_literal(-1) == "-1"


def test_format_meta_literal_invalid_type_raises() -> None:
    """Lines 328-329: unsupported type such as float must raise TypeError."""
    with pytest.raises(TypeError, match="Invalid meta value type 'float'"):
        format_meta_literal(3.14)


def test_format_nonempty_quoted_value_returns_escaped_string() -> None:
    """Line 351: valid string with no forbidden chars must return its escaped form."""
    result = format_nonempty_quoted_value("hello world", "Import")
    assert result == "hello world"


def test_format_boolean_literal_returns_string_for_both_values() -> None:
    """Line 383: True must return 'true' and False must return 'false'."""
    assert format_boolean_literal(True) == "true"
    assert format_boolean_literal(False) == "false"
