"""Regression tests for yaraast.ast.rules targeting previously uncovered lines.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Missing-line coverage targets (as of the coverage snapshot):
  38-48  _validate_yara_identifier: non-string TypeError, valid return, ValueError
  52-54  _validate_quoted_field_text: quote and control-char ValueError
  66-70  Import.validate_structure: module body and alias branch
  84-85  Include.validate_structure body
  99-100 Tag.validate_structure body
  143-145 Rule.from_raw body
  158    _normalize_modifiers: empty-string branch
  160-165 _normalize_modifiers: non-empty string (success and except paths)
  177    _normalize_modifiers: non-list/tuple/str/None fallback
  183    _normalize_meta: None branch
  188    _normalize_meta: scalar (non-list/dict) fallback
  192-224 Rule.validate_structure full body
  256    _validated_meta_entries: None-meta early-return
  258    _validated_meta_entries: dict-meta branch
  269-270 _validated_meta_entries: Meta-node branch
  308->307 get_meta_value loop iteration branch
  310    get_meta_value: default return when key absent

"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, RuleModifier, RuleModifierType
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaType
from yaraast.ast.rules import Import, Include, Rule, Tag, _validate_yara_identifier
from yaraast.ast.strings import PlainString

# ---------------------------------------------------------------------------
# _validate_yara_identifier (lines 38-48)
# ---------------------------------------------------------------------------


class TestValidateYaraIdentifierDirect:
    """Exercise the non-string TypeError path (lines 39-40) by calling the function directly.

    The public validate_structure entry points call _require_nonempty_string or
    _require_optional_nonempty_string before _validate_yara_identifier, which means
    they raise TypeError earlier for non-string inputs and never reach line 39.
    Calling the module-level function directly is the only way to cover lines 39-40
    through real production code execution.
    """

    def test_non_string_raises_type_error(self) -> None:
        """A non-string argument triggers the isinstance guard at line 38 (lines 39-40)."""
        with pytest.raises(
            TypeError, match=r"Rule.*identifier must be a string for libyara output"
        ):
            _validate_yara_identifier(42, "rule")

    def test_none_raises_type_error(self) -> None:
        """None is not a string and triggers lines 39-40."""
        with pytest.raises(TypeError, match=r"Tag.*identifier must be a string for libyara output"):
            _validate_yara_identifier(None, "tag")

    def test_valid_string_returns_the_string(self) -> None:
        """A valid identifier string is returned unchanged (line 46)."""
        result = _validate_yara_identifier("valid_name", "rule")
        assert result == "valid_name"

    def test_keyword_string_raises_value_error(self) -> None:
        """A YARA keyword string raises ValueError (lines 47-48)."""
        with pytest.raises(ValueError, match="Invalid rule identifier 'rule' for libyara output"):
            _validate_yara_identifier("rule", "rule")


class TestValidateYaraIdentifierViaTag:
    """Exercise _validate_yara_identifier through Tag.validate_structure.

    Tag.validate_structure calls _require_nonempty_string then _validate_yara_identifier,
    which is the simplest public surface that reaches lines 38-48 directly.
    """

    def test_valid_identifier_is_returned(self) -> None:
        """A syntactically correct, non-keyword identifier passes validation.

        This exercises the successful return at line 46.
        """
        tag = Tag(name="mytag")
        tag.validate_structure()

    def test_identifier_that_is_a_keyword_raises_value_error(self) -> None:
        """A YARA keyword is rejected with ValueError (lines 47-48)."""
        tag = Tag(name="rule")
        with pytest.raises(ValueError, match=r"Invalid tag identifier.*for libyara output"):
            tag.validate_structure()

    def test_identifier_exceeding_max_length_raises_value_error(self) -> None:
        """An identifier longer than YARA_IDENTIFIER_MAX_LENGTH is rejected (lines 47-48)."""
        tag = Tag(name="a" * 200)
        with pytest.raises(ValueError, match=r"Invalid tag identifier.*for libyara output"):
            tag.validate_structure()

    def test_identifier_with_invalid_pattern_raises_value_error(self) -> None:
        """An identifier starting with a digit is rejected (lines 47-48)."""
        tag = Tag(name="1invalid")
        with pytest.raises(ValueError, match=r"Invalid tag identifier.*for libyara output"):
            tag.validate_structure()


class TestValidateYaraIdentifierViaImportAlias:
    """Exercise the non-string TypeError path (lines 38-40) via Import.validate_structure.

    Import.validate_structure calls _validate_yara_identifier for alias only when
    alias is not None.  Passing a non-string alias reaches line 38.
    """

    def test_non_string_alias_raises_type_error(self) -> None:
        """A numeric alias triggers the isinstance check at line 38 and raises TypeError."""
        node = Import(module="pe", alias=cast(Any, 42))
        with pytest.raises(TypeError, match=r"Import alias.*must be a string"):
            node.validate_structure()


# ---------------------------------------------------------------------------
# _validate_quoted_field_text (lines 52-54)
# ---------------------------------------------------------------------------


class TestValidateQuotedFieldText:
    """Exercise _validate_quoted_field_text through validate_structure of Import / Include.

    Both Import and Include call _validate_quoted_field_text on their string
    fields, which exercises the ValueError branch at lines 52-54.
    """

    def test_import_module_with_embedded_quote_raises_value_error(self) -> None:
        """A double-quote inside an Import module field triggers line 53-54."""
        node = Import(module='pe"bad')
        with pytest.raises(ValueError, match="must not contain quotes or control characters"):
            node.validate_structure()

    def test_include_path_with_control_character_raises_value_error(self) -> None:
        """A control character (ord < 0x20) inside an Include path triggers line 53-54."""
        node = Include(path="bad\x01path")
        with pytest.raises(ValueError, match="must not contain quotes or control characters"):
            node.validate_structure()

    def test_include_path_with_del_character_raises_value_error(self) -> None:
        """The DEL character (0x7F) inside an Include path is also rejected."""
        node = Include(path="bad\x7fpath")
        with pytest.raises(ValueError, match="must not contain quotes or control characters"):
            node.validate_structure()


# ---------------------------------------------------------------------------
# Import.validate_structure (lines 66-70)
# ---------------------------------------------------------------------------


class TestImportValidateStructure:
    """Cover Import.validate_structure body (lines 66-70)."""

    def test_valid_import_without_alias_passes(self) -> None:
        """validate_structure returns without error for a plain import (lines 66-67)."""
        node = Import(module="pe")
        node.validate_structure()

    def test_valid_import_with_alias_passes(self) -> None:
        """The alias branch at lines 68-70 executes when alias is set."""
        node = Import(module="pe", alias="pe_alias")
        node.validate_structure()

    def test_import_with_keyword_alias_raises_value_error(self) -> None:
        """_validate_yara_identifier raises ValueError for a keyword alias (line 70 path)."""
        node = Import(module="pe", alias="rule")
        with pytest.raises(ValueError, match="Invalid import alias identifier"):
            node.validate_structure()


# ---------------------------------------------------------------------------
# Include.validate_structure (lines 84-85)
# ---------------------------------------------------------------------------


class TestIncludeValidateStructure:
    """Cover Include.validate_structure body (lines 84-85)."""

    def test_valid_include_path_passes(self) -> None:
        """A clean path passes validation without error."""
        node = Include(path="other.yar")
        node.validate_structure()

    def test_include_path_with_quote_raises_value_error(self) -> None:
        """_validate_quoted_field_text is called and rejects a quoted path."""
        node = Include(path='bad"path.yar')
        with pytest.raises(ValueError, match="must not contain quotes or control characters"):
            node.validate_structure()


# ---------------------------------------------------------------------------
# Tag.validate_structure (lines 99-100)
# ---------------------------------------------------------------------------


class TestTagValidateStructure:
    """Cover Tag.validate_structure body (lines 99-100)."""

    def test_valid_tag_passes(self) -> None:
        """A well-formed tag identifier passes without error (lines 99-100)."""
        tag = Tag(name="malware")
        tag.validate_structure()

    def test_tag_with_keyword_name_raises_value_error(self) -> None:
        """A keyword tag name raises ValueError via _validate_yara_identifier."""
        tag = Tag(name="strings")
        with pytest.raises(ValueError, match="Invalid tag identifier"):
            tag.validate_structure()


# ---------------------------------------------------------------------------
# Rule.from_raw (lines 143-145)
# ---------------------------------------------------------------------------


class TestRuleFromRaw:
    """Cover Rule.from_raw factory method (lines 143-145)."""

    def test_from_raw_with_string_modifiers_and_dict_meta(self) -> None:
        """from_raw normalizes string modifiers and dict meta and returns a Rule."""
        rule = Rule.from_raw("test_rule", modifiers="private", meta={"author": "me"})
        assert rule.name == "test_rule"
        assert rule.is_private
        assert rule.get_meta_value("author") == "me"

    def test_from_raw_with_no_modifiers_or_meta(self) -> None:
        """from_raw with all defaults builds an empty Rule correctly."""
        rule = Rule.from_raw("minimal")
        assert rule.name == "minimal"
        assert not rule.is_private
        assert not rule.is_global

    def test_from_raw_with_list_modifiers_and_list_meta(self) -> None:
        """from_raw accepts already-normalized modifiers and meta lists."""
        mod = RuleModifier(modifier_type=RuleModifierType.GLOBAL)
        entry = MetaEntry.from_key_value("desc", "test")
        rule = Rule.from_raw("full_rule", modifiers=[mod], meta=[entry])
        assert rule.is_global
        assert rule.get_meta_value("desc") == "test"


# ---------------------------------------------------------------------------
# Rule._normalize_modifiers (lines 158, 160-165, 177)
# ---------------------------------------------------------------------------


class TestNormalizeModifiers:
    """Cover _normalize_modifiers branches not hit by existing tests."""

    def test_empty_string_modifier_returns_empty_list(self) -> None:
        """An empty string input returns [] immediately (line 158-161)."""
        result = Rule._normalize_modifiers("")
        assert result == []

    def test_valid_string_modifier_converted_to_rule_modifier(self) -> None:
        """A recognized modifier string is converted to a RuleModifier (lines 162-163)."""
        result = Rule._normalize_modifiers("private")
        assert len(result) == 1
        assert isinstance(result[0], RuleModifier)
        assert result[0].modifier_type == RuleModifierType.PRIVATE

    def test_unknown_string_modifier_stored_as_string(self) -> None:
        """A string that fails RuleModifier.from_string is stored as-is (lines 164-165)."""
        result = Rule._normalize_modifiers("vendor_extension")
        assert result == ["vendor_extension"]

    def test_list_with_unknown_string_element_stored_as_string(self) -> None:
        """An unknown string element inside a list is stored as-is (lines 172-173)."""
        result = Rule._normalize_modifiers(["vendor_extension"])
        assert result == ["vendor_extension"]

    def test_list_with_known_string_element_converts_to_rule_modifier(self) -> None:
        """A recognized string element inside a list is converted (lines 170-171)."""
        result = Rule._normalize_modifiers(["private"])
        assert len(result) == 1
        assert isinstance(result[0], RuleModifier)

    def test_non_list_non_str_non_none_wrapped_in_list(self) -> None:
        """A scalar non-string value is wrapped in a list as a fallback (line 177)."""
        sentinel = object()
        result = Rule._normalize_modifiers(cast(Any, sentinel))
        assert result == [sentinel]


# ---------------------------------------------------------------------------
# Rule._normalize_meta (lines 183, 188)
# ---------------------------------------------------------------------------


class TestNormalizeMeta:
    """Cover _normalize_meta branches not hit by existing tests."""

    def test_none_meta_returns_empty_list(self) -> None:
        """_normalize_meta(None) returns an empty list (line 183)."""
        result = Rule._normalize_meta(None)
        assert result == []

    def test_scalar_meta_wrapped_in_list(self) -> None:
        """A scalar non-dict, non-list value is wrapped in a list (line 188)."""
        entry = MetaEntry.from_key_value("key", "value")
        result = Rule._normalize_meta(cast(Any, entry))
        assert result == [entry]


# ---------------------------------------------------------------------------
# Rule.validate_structure (lines 192-224)
# ---------------------------------------------------------------------------


class TestRuleValidateStructure:
    """Cover Rule.validate_structure comprehensively (lines 192-224)."""

    def test_minimal_rule_with_no_optional_fields_passes(self) -> None:
        """A Rule with only a name passes validate_structure (core lines 192-210)."""
        rule = Rule(name="minimal_rule")
        rule.validate_structure()

    def test_rule_with_tags_validates_each_tag(self) -> None:
        """Tags are iterated and each tag.validate_structure() is called (lines 213-214)."""
        rule = Rule(name="tagged_rule", tags=[Tag(name="mytag"), Tag(name="othertag")])
        rule.validate_structure()

    def test_rule_with_string_definition_validates_string(self) -> None:
        """Strings are iterated and validate_structure() is called on each (lines 217-220)."""
        ps = PlainString(identifier="$a", value="malware")
        rule = Rule(name="string_rule", strings=[ps])
        rule.validate_structure()

    def test_rule_with_condition_expression_validates_condition(self) -> None:
        """A non-None condition triggers lines 211-212 and 221-224."""
        cond = BooleanLiteral(value=True)
        rule = Rule(name="cond_rule", condition=cond)
        rule.validate_structure()

    def test_rule_with_all_fields_passes_full_validate_structure(self) -> None:
        """All branches in validate_structure are exercised simultaneously."""
        tag = Tag(name="malwaretag")
        ps = PlainString(identifier="$b", value="badfile")
        cond = BooleanLiteral(value=False)
        mod = RuleModifier(modifier_type=RuleModifierType.GLOBAL)
        pragma = InRulePragma(
            pragma=Pragma(PragmaType.DEFINE, "define"),
            position="before_strings",
        )
        rule = Rule(
            name="full_rule",
            modifiers=[mod],
            tags=[tag],
            meta={"desc": "test"},
            strings=[ps],
            condition=cond,
            pragmas=[pragma],
        )
        rule.validate_structure()

    def test_rule_with_keyword_name_raises_value_error(self) -> None:
        """A keyword rule name raises ValueError in validate_structure (line 193)."""
        rule = Rule(name="rule")
        with pytest.raises(ValueError, match="Invalid rule identifier"):
            rule.validate_structure()


# ---------------------------------------------------------------------------
# Rule._validated_meta_entries (lines 256, 258, 269-270)
# ---------------------------------------------------------------------------


class TestValidatedMetaEntries:
    """Cover _validated_meta_entries branches not hit by existing tests."""

    def test_none_meta_returns_empty_list(self) -> None:
        """When self.meta is None, _validated_meta_entries returns [] (line 256)."""
        rule = Rule(name="r1")
        rule.meta = None
        result = rule._validated_meta_entries()
        assert result == []

    def test_dict_meta_returns_meta_entry_list(self) -> None:
        """A dict assigned to self.meta is converted to MetaEntry list (line 258)."""
        rule = Rule(name="r2")
        rule.meta = {"author": "me", "version": "1"}
        entries = rule._validated_meta_entries()
        assert {e.key for e in entries} == {"author", "version"}
        assert rule._validated_meta_entries()[0].value in {"me", "1"}

    def test_meta_node_converted_to_meta_entry(self) -> None:
        """A Meta node in the meta list is converted to MetaEntry (lines 269-270)."""
        meta_node = Meta(key="owner", value="team")
        rule = Rule(name="r3")
        rule.meta = [meta_node]
        entries = rule._validated_meta_entries()
        assert len(entries) == 1
        assert entries[0].key == "owner"
        assert entries[0].value == "team"

    def test_mixed_meta_entry_and_meta_node(self) -> None:
        """Both MetaEntry and Meta node types coexist in the list correctly."""
        entry = MetaEntry.from_key_value("direct", 42)
        meta_node = Meta(key="indirect", value="value")
        rule = Rule(name="r4")
        rule.meta = [entry, meta_node]
        entries = rule._validated_meta_entries()
        assert len(entries) == 2
        keys = {e.key for e in entries}
        assert keys == {"direct", "indirect"}


# ---------------------------------------------------------------------------
# Rule.get_meta_value default return (lines 308->307 branch, 310)
# ---------------------------------------------------------------------------


class TestGetMetaValueDefault:
    """Cover the default-return branch of get_meta_value (lines 308->307, 310)."""

    def test_missing_key_returns_none_by_default(self) -> None:
        """When the key is absent and no default is given, None is returned (line 310)."""
        rule = Rule(name="r1", meta={"author": "me"})
        result = rule.get_meta_value("nonexistent")
        assert result is None

    def test_missing_key_returns_supplied_default(self) -> None:
        """When the key is absent, the caller-supplied default is returned (line 310)."""
        rule = Rule(name="r2", meta={"author": "me"})
        result = rule.get_meta_value("nonexistent", default="fallback")
        assert result == "fallback"

    def test_empty_meta_returns_default(self) -> None:
        """With an empty meta list, any key lookup falls through to the default (line 310)."""
        rule = Rule(name="r3")
        result = rule.get_meta_value("anything", default=99)
        assert result == 99

    def test_matching_key_does_not_return_default(self) -> None:
        """When the key exists, the loop returns early (exercises 308->307 vs. 310 branch)."""
        rule = Rule(name="r4", meta={"key": "found"})
        result = rule.get_meta_value("key", default="never")
        assert result == "found"

    def test_multiple_entries_traversed_before_returning_default(self) -> None:
        """The reversed iteration visits all entries before falling to line 310.

        This exercises the 308->307 branch (loop iterates with no match).
        """
        rule = Rule(
            name="r5",
            meta=[
                MetaEntry.from_key_value("a", 1),
                MetaEntry.from_key_value("b", 2),
                MetaEntry.from_key_value("c", 3),
            ],
        )
        result = rule.get_meta_value("z", default="default_val")
        assert result == "default_val"
