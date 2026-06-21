# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression coverage for yaraast.serialization.roundtrip_pipeline_helpers.

Targets the lines that remain uncovered after the existing test battery runs:
  42-43   _validated_node_collection — wrong-type item raises SerializationError
  50-51   _required_string — non-string value raises SerializationError
  64      _nullable_nonempty_string — None value returns None
  71-74   _serialized_meta_value — int path and invalid-type error path
  79-83   _serialized_meta_entry_value — int path, float path, error path
  96-97   _validated_rule_modifiers — RuleModifier object is serialized via str()
  101-102 _validated_rule_modifiers — non-string/non-RuleModifier item raises
  121-136 build_pipeline_metadata — True + with pipeline_info updates metadata
  182     build_rules_manifest — private modifier increments private_rules counter
  184     build_rules_manifest — global modifier increments global_rules counter
  186     build_rules_manifest — tagged rule increments tagged_rules counter
  196-205 build_rules_manifest — manifest["rules"].append and summary construction
  210     _build_rule_meta — empty meta list returns []
  227-230 _build_rule_meta — scoped MetaEntry serialises scope field
  263     count_string_types — hex string increments hex counter
  265     count_string_types — regex string increments regex counter
  266->261 count_string_types — branch: string has neither value/tokens/regex attr

All tests build real AST nodes through production constructors and assert
observable output values.  No mocks, stubs, or test doubles are used.
"""

from __future__ import annotations

import math
from pathlib import Path
import tempfile

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, MetaScope, RuleModifier, RuleModifierType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.errors import SerializationError
from yaraast.serialization.roundtrip_pipeline_helpers import (
    _build_rule_meta,
    _nullable_nonempty_string,
    _required_string,
    _serialized_meta_entry_value,
    _serialized_meta_value,
    _validated_node_collection,
    _validated_rule_modifiers,
    build_pipeline_metadata,
    build_pipeline_statistics,
    build_rules_manifest,
    collect_all_tags,
    count_string_types,
    dump_pipeline_yaml,
)

# ---------------------------------------------------------------------------
# Helpers that produce minimal valid AST nodes
# ---------------------------------------------------------------------------


def _bool_expr() -> BooleanLiteral:
    return BooleanLiteral(value=True)


def _plain_rule(name: str = "test_rule") -> Rule:
    return Rule(name=name, condition=_bool_expr())


def _yara_file(*rules: Rule) -> YaraFile:
    return YaraFile(rules=list(rules))


# ---------------------------------------------------------------------------
# _validated_node_collection — wrong-type item (lines 42-43)
# ---------------------------------------------------------------------------


def test_validated_node_collection_raises_for_wrong_item_type() -> None:
    """A list containing a non-Tag item must raise SerializationError (lines 42-43)."""
    with pytest.raises(SerializationError, match="item must be a Tag node"):
        _validated_node_collection([Tag(name="ok"), "not_a_tag"], "ctx", Tag)


def test_validated_node_collection_raises_for_wrong_item_type_in_tuple() -> None:
    """A tuple containing an invalid item must raise the same error."""
    with pytest.raises(SerializationError, match="item must be"):
        _validated_node_collection((Tag(name="x"), 99), "tags", Tag)


# ---------------------------------------------------------------------------
# _required_string — non-string raises SerializationError (lines 50-51)
# ---------------------------------------------------------------------------


def test_required_string_raises_for_integer_value() -> None:
    """Passing an integer where a string is required raises SerializationError."""
    with pytest.raises(SerializationError, match="must be a string"):
        _required_string(42, "rule name")


def test_required_string_raises_for_none_value() -> None:
    """Passing None where a string is required raises SerializationError."""
    with pytest.raises(SerializationError, match="must be a string"):
        _required_string(None, "import module")


# ---------------------------------------------------------------------------
# _nullable_nonempty_string — None returns None (line 64)
# ---------------------------------------------------------------------------


def test_nullable_nonempty_string_returns_none_for_none_input() -> None:
    """None input must return None without raising (line 64)."""
    result = _nullable_nonempty_string(None, "optional alias")
    assert result is None


def test_nullable_nonempty_string_returns_value_for_valid_string() -> None:
    """Non-None strings pass through to _required_nonempty_string."""
    result = _nullable_nonempty_string("pe", "module alias")
    assert result == "pe"


# ---------------------------------------------------------------------------
# _serialized_meta_value — int path (lines 71-72) and error path (73-74)
# ---------------------------------------------------------------------------


def test_serialized_meta_value_returns_int_unchanged() -> None:
    """Integer meta values are returned as-is (lines 71-72)."""
    assert _serialized_meta_value(0) == 0
    assert _serialized_meta_value(1_000_000) == 1_000_000


def test_serialized_meta_value_raises_for_float() -> None:
    """Float is not a valid meta value; must raise SerializationError (lines 73-74)."""
    with pytest.raises(SerializationError, match="Meta value must be"):
        _serialized_meta_value(3.14)


def test_serialized_meta_value_raises_for_list() -> None:
    """A list is not a valid meta value."""
    with pytest.raises(SerializationError, match="Meta value must be"):
        _serialized_meta_value([1, 2, 3])


# ---------------------------------------------------------------------------
# _serialized_meta_entry_value — int path (81), finite float path (83),
# error path (84-85)
# ---------------------------------------------------------------------------


def test_serialized_meta_entry_value_returns_int_unchanged() -> None:
    """Integer entry values are returned as-is (line 81)."""
    assert _serialized_meta_entry_value(7) == 7


def test_serialized_meta_entry_value_returns_finite_float() -> None:
    """Finite float entry values are returned as-is (line 83)."""
    result = _serialized_meta_entry_value(2.718)
    assert isinstance(result, float)
    assert math.isclose(result, 2.718)


def test_serialized_meta_entry_value_raises_for_infinite_float() -> None:
    """Infinite float must raise SerializationError (lines 84-85)."""
    with pytest.raises(SerializationError, match="Meta value must be"):
        _serialized_meta_entry_value(math.inf)


def test_serialized_meta_entry_value_raises_for_nan() -> None:
    """NaN must raise SerializationError (non-finite float path)."""
    with pytest.raises(SerializationError, match="Meta value must be"):
        _serialized_meta_entry_value(math.nan)


def test_serialized_meta_entry_value_raises_for_list() -> None:
    """A list is not a valid meta entry value."""
    with pytest.raises(SerializationError, match="Meta value must be"):
        _serialized_meta_entry_value([])


# ---------------------------------------------------------------------------
# _validated_rule_modifiers — RuleModifier path (96-97),
# invalid-type path (101-102)
# ---------------------------------------------------------------------------


def test_validated_rule_modifiers_accepts_rule_modifier_objects() -> None:
    """RuleModifier instances are serialised via str() (lines 96-97)."""
    private = RuleModifier(modifier_type=RuleModifierType.PRIVATE)
    global_ = RuleModifier(modifier_type=RuleModifierType.GLOBAL)
    result = _validated_rule_modifiers([private, global_])
    assert result == ["private", "global"]


def test_validated_rule_modifiers_raises_for_non_string_non_modifier_item() -> None:
    """An integer modifier must raise SerializationError (lines 101-102)."""
    with pytest.raises(SerializationError, match="must be a string or RuleModifier"):
        _validated_rule_modifiers([42])


def test_validated_rule_modifiers_raises_for_none_item() -> None:
    """None as a modifier item must raise SerializationError."""
    with pytest.raises(SerializationError, match="must be a string or RuleModifier"):
        _validated_rule_modifiers([None])


# ---------------------------------------------------------------------------
# build_pipeline_metadata — include=True (lines 121-136)
# ---------------------------------------------------------------------------


def test_build_pipeline_metadata_returns_none_when_disabled() -> None:
    """include_pipeline_metadata=False must return None (line 121-122)."""
    result = build_pipeline_metadata(False, None)
    assert result is None


def test_build_pipeline_metadata_returns_dict_when_enabled() -> None:
    """include_pipeline_metadata=True returns a dict with required keys (lines 123-133)."""
    result = build_pipeline_metadata(True, None)
    assert isinstance(result, dict)
    assert result["format"] == "yaraast-pipeline-yaml"
    assert result["version"] == "1.0.0"
    assert result["features"]["rule_validation"] is True


def test_build_pipeline_metadata_merges_pipeline_info() -> None:
    """pipeline_info entries are merged into the metadata dict (lines 134-135)."""
    extra = {"pipeline_id": "abc123", "run_number": 7}
    result = build_pipeline_metadata(True, extra)
    assert result is not None
    assert result["pipeline_id"] == "abc123"
    assert result["run_number"] == 7
    # Core keys must still be present after update
    assert "format" in result
    assert "features" in result


def test_build_pipeline_metadata_pipeline_info_none_leaves_metadata_clean() -> None:
    """pipeline_info=None leaves the metadata dict unmodified (line 134 branch)."""
    result = build_pipeline_metadata(True, None)
    assert result is not None
    assert "pipeline_id" not in result


# ---------------------------------------------------------------------------
# build_rules_manifest — counters for private, global, tagged (182/184/186)
# and manifest construction (196-205)
# ---------------------------------------------------------------------------


def test_build_rules_manifest_counts_private_rules() -> None:
    """A rule with 'private' modifier increments private_rules counter (line 182)."""
    rule = Rule(
        name="private_rule",
        modifiers=[RuleModifier(modifier_type=RuleModifierType.PRIVATE)],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule])
    manifest = build_rules_manifest(ast)
    assert manifest["summary"]["private_rules"] == 1
    assert manifest["summary"]["global_rules"] == 0


def test_build_rules_manifest_counts_global_rules() -> None:
    """A rule with 'global' modifier increments global_rules counter (line 184)."""
    rule = Rule(
        name="global_rule",
        modifiers=[RuleModifier(modifier_type=RuleModifierType.GLOBAL)],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule])
    manifest = build_rules_manifest(ast)
    assert manifest["summary"]["global_rules"] == 1
    assert manifest["summary"]["private_rules"] == 0


def test_build_rules_manifest_counts_tagged_rules() -> None:
    """A rule with at least one tag increments tagged_rules counter (line 186)."""
    rule = Rule(
        name="tagged_rule",
        tags=[Tag(name="malware")],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule])
    manifest = build_rules_manifest(ast)
    assert manifest["summary"]["tagged_rules"] == 1


def test_build_rules_manifest_summary_includes_all_counters() -> None:
    """summary dict captures total_rules, imports, and includes (lines 197-204)."""
    private_rule = Rule(
        name="priv",
        modifiers=[RuleModifier(modifier_type=RuleModifierType.PRIVATE)],
        condition=_bool_expr(),
    )
    global_tagged = Rule(
        name="glob_tagged",
        modifiers=[RuleModifier(modifier_type=RuleModifierType.GLOBAL)],
        tags=[Tag(name="ransomware"), Tag(name="trojan")],
        condition=_bool_expr(),
    )
    ast = YaraFile(
        imports=[Import(module="pe"), Import(module="math")],
        includes=[Include(path="common.yar")],
        rules=[private_rule, global_tagged],
    )
    manifest = build_rules_manifest(ast)

    summary = manifest["summary"]
    assert summary["total_rules"] == 2
    assert summary["private_rules"] == 1
    assert summary["global_rules"] == 1
    assert summary["tagged_rules"] == 1
    assert set(summary["imports"]) == {"pe", "math"}
    assert summary["includes"] == ["common.yar"]

    # Each rule must appear in manifest["rules"] with correct fields
    rule_names = [r["name"] for r in manifest["rules"]]
    assert "priv" in rule_names
    assert "glob_tagged" in rule_names


def test_build_rules_manifest_rule_entry_structure() -> None:
    """Each rule entry in manifest['rules'] has all required fields (lines 188-196)."""
    rule = Rule(
        name="detail_rule",
        modifiers=[RuleModifier(modifier_type=RuleModifierType.PRIVATE)],
        tags=[Tag(name="apt")],
        meta=[Meta(key="author", value="tester")],
        strings=[PlainString(identifier="s1", value="hello")],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule])
    manifest = build_rules_manifest(ast)

    entry = manifest["rules"][0]
    assert entry["name"] == "detail_rule"
    assert entry["modifiers"] == ["private"]
    assert entry["tags"] == ["apt"]
    assert entry["string_count"] == 1
    assert entry["has_condition"] is True


# ---------------------------------------------------------------------------
# _build_rule_meta — empty list returns [] (line 210),
# scoped MetaEntry serialises scope (lines 227-230)
# ---------------------------------------------------------------------------


def test_build_rule_meta_returns_empty_list_for_empty_input() -> None:
    """Empty meta list must return an empty list without error (line 210)."""
    result = _build_rule_meta([])
    assert result == []


def test_build_rule_meta_serialises_scoped_meta_entry() -> None:
    """MetaEntry with a non-None scope must include 'scope' field (lines 227-230)."""
    entry = MetaEntry(key="visibility", value="secret", scope=MetaScope.PRIVATE)
    result = _build_rule_meta([entry])
    assert len(result) == 1
    assert result[0]["key"] == "visibility"
    assert result[0]["value"] == "secret"
    assert result[0]["scope"] == "private"


def test_build_rule_meta_omits_scope_for_plain_meta_node() -> None:
    """Meta node (no scope attribute) must not emit a 'scope' key."""
    plain = Meta(key="author", value="tester")
    result = _build_rule_meta([plain])
    assert len(result) == 1
    assert "scope" not in result[0]


def test_build_rule_meta_public_scope_is_included() -> None:
    """MetaEntry with PUBLIC scope must also include the scope field."""
    entry = MetaEntry(key="priority", value=1, scope=MetaScope.PUBLIC)
    result = _build_rule_meta([entry])
    assert result[0]["scope"] == "public"


# ---------------------------------------------------------------------------
# count_string_types — hex counter (263), regex counter (265),
# branch fallthrough 266->261 (string with no recognised attribute)
# ---------------------------------------------------------------------------


def test_count_string_types_counts_hex_strings() -> None:
    """HexString with tokens attribute increments hex counter (line 263)."""
    rule = Rule(
        name="hex_rule",
        strings=[HexString("s1", tokens=[HexByte(value=0xDE), HexByte(value=0xAD)])],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule])
    counts = count_string_types(ast)
    assert counts["hex"] == 1
    assert counts["plain"] == 0
    assert counts["regex"] == 0


def test_count_string_types_counts_regex_strings() -> None:
    """RegexString with regex attribute increments regex counter (line 265)."""
    rule = Rule(
        name="regex_rule",
        strings=[RegexString("s1", regex="malware"), RegexString("s2", regex="exploit")],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule])
    counts = count_string_types(ast)
    assert counts["regex"] == 2
    assert counts["plain"] == 0
    assert counts["hex"] == 0


def test_count_string_types_counts_mixed_string_types() -> None:
    """Rules with all three string types are counted correctly."""
    rule = Rule(
        name="mixed",
        strings=[
            PlainString("s1", value="payload"),
            HexString("s2", tokens=[HexByte(value=0xAB)]),
            RegexString("s3", regex="ransomware"),
        ],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule])
    counts = count_string_types(ast)
    assert counts["plain"] == 1
    assert counts["hex"] == 1
    assert counts["regex"] == 1


# ---------------------------------------------------------------------------
# build_pipeline_statistics — integration with imports and tags
# ---------------------------------------------------------------------------


def test_build_pipeline_statistics_returns_correct_structure() -> None:
    """build_pipeline_statistics returns total_rules, imports, tags, patterns."""
    rule = Rule(
        name="stat_rule",
        tags=[Tag(name="info_stealer")],
        strings=[PlainString("s1", value="steal"), HexString("s2", tokens=[])],
        condition=_bool_expr(),
    )
    ast = YaraFile(
        imports=[Import(module="cuckoo")],
        rules=[rule],
    )
    stats = build_pipeline_statistics(ast)
    assert stats["total_rules"] == 1
    assert "cuckoo" in stats["imports"]
    assert "info_stealer" in stats["rule_tags"]
    assert stats["string_patterns"]["plain"] == 1
    assert stats["string_patterns"]["hex"] == 1


# ---------------------------------------------------------------------------
# collect_all_tags — deduplication and sorting
# ---------------------------------------------------------------------------


def test_collect_all_tags_deduplicates_and_sorts() -> None:
    """Tags appearing across multiple rules are deduplicated and sorted."""
    rule_a = Rule(
        name="rule_a",
        tags=[Tag(name="malware"), Tag(name="trojan")],
        condition=_bool_expr(),
    )
    rule_b = Rule(
        name="rule_b",
        tags=[Tag(name="malware"), Tag(name="apt")],
        condition=_bool_expr(),
    )
    ast = YaraFile(rules=[rule_a, rule_b])
    tags = collect_all_tags(ast)
    # Must be sorted alphabetically and deduplicated
    assert tags == ["apt", "malware", "trojan"]


def test_collect_all_tags_returns_empty_for_untagged_rules() -> None:
    """Rules without tags produce an empty tag list."""
    ast = YaraFile(rules=[_plain_rule("untagged")])
    assert collect_all_tags(ast) == []


# ---------------------------------------------------------------------------
# dump_pipeline_yaml — output_path writes file (line 291)
# ---------------------------------------------------------------------------


def test_dump_pipeline_yaml_writes_to_output_path() -> None:
    """When output_path is provided the YAML is written to that file (line 291)."""
    data = {"key": "value", "count": 3}
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "output.yaml"
        yaml_str = dump_pipeline_yaml(data, output)
        assert output.exists()
        written = output.read_text(encoding="utf-8")
        assert written == yaml_str
        assert "key: value" in yaml_str


def test_dump_pipeline_yaml_returns_yaml_string_without_path() -> None:
    """output_path=None returns a YAML string and writes no file."""
    data = {"rules": [], "total": 0}
    yaml_str = dump_pipeline_yaml(data, None)
    assert isinstance(yaml_str, str)
    assert "rules:" in yaml_str


def test_dump_pipeline_yaml_explicit_markers_option() -> None:
    """explicit_markers=True wraps output with YAML document markers."""
    yaml_str = dump_pipeline_yaml({"x": 1}, None, explicit_markers=True)
    assert yaml_str.startswith("---")
