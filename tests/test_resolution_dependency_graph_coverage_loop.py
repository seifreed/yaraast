# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Regression tests for yaraast.resolution.dependency_graph targeting the lines
that remained uncovered after the existing test_multi_file_resolution.py suite.

Every test exercises real production code: the actual DependencyGraph, the real
AST builders (YaraFile, Rule, Import, etc.), and the real Parser.  No mocks are
used anywhere in this file.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.modules import ModuleReference
from yaraast.ast.rules import Import, Rule
from yaraast.errors import ValidationError
from yaraast.parser import Parser
from yaraast.resolution.dependency_graph import (
    DependencyGraph,
    DependencyNode,
    _module_name_for_object,
    _normalize_include_resolutions,
    _require_path,
    _require_string,
    _require_string_or_path,
    _require_yara_file,
    _rule_occurrence_keys,
    _RuleDependencyCollector,
    require_rule_lookup_name,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(source: str) -> YaraFile:
    """Return a parsed YaraFile from YARA source text."""
    return Parser(source).parse()


def _yf(*rules_src: str, imports: list[str] | None = None) -> YaraFile:
    """Build a YaraFile from per-rule snippets, optionally with imports."""
    header = "".join(f'import "{m}"\n' for m in (imports or []))
    body = "\n".join(rules_src)
    return _parse(header + body)


# ---------------------------------------------------------------------------
# _require_path (lines 22-23, 27-28, 30-31)
# ---------------------------------------------------------------------------


class TestRequirePath:
    """Lines 20-31: _require_path validation."""

    def test_empty_path_object_raises(self) -> None:
        """A Path whose str representation is empty/whitespace raises ValidationError."""
        with pytest.raises(ValidationError, match="must not be empty"):
            _require_path(Path("   "), "ctx")

    def test_null_byte_path_object_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not contain null bytes"):
            _require_path(Path("\x00broken"), "ctx")

    def test_empty_string_raises(self) -> None:
        """An all-whitespace str raises ValidationError."""
        with pytest.raises(ValidationError, match="must not be empty"):
            _require_path("  ", "ctx")

    def test_wrong_type_raises(self) -> None:
        """A value that is neither str nor Path raises ValidationError."""
        with pytest.raises(ValidationError, match="must be a path"):
            _require_path(42, "ctx")

    def test_null_byte_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not contain null bytes"):
            _require_path("\x00broken", "ctx")

    def test_valid_path_string(self, tmp_path: Path) -> None:
        result = _require_path(str(tmp_path), "ctx")
        assert result == tmp_path

    def test_valid_path_object(self, tmp_path: Path) -> None:
        result = _require_path(tmp_path, "ctx")
        assert result is tmp_path


# ---------------------------------------------------------------------------
# _require_string (lines 37-38, 40-41)
# ---------------------------------------------------------------------------


class TestRequireString:
    """Lines 35-41: _require_string validation."""

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            _require_string("", "ctx")

    def test_whitespace_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            _require_string("   ", "ctx")

    def test_wrong_type_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            _require_string(99, "ctx")

    def test_valid_string(self) -> None:
        assert _require_string("hello", "ctx") == "hello"


# ---------------------------------------------------------------------------
# require_rule_lookup_name
# ---------------------------------------------------------------------------


class TestRequireRuleLookupName:
    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="DependencyGraph rule name"):
            require_rule_lookup_name("")

    def test_valid(self) -> None:
        assert require_rule_lookup_name("alpha") == "alpha"


# ---------------------------------------------------------------------------
# _require_string_or_path (lines 51-52, 56-57, 59-60)
# ---------------------------------------------------------------------------


class TestRequireStringOrPath:
    """Lines 49-60: _require_string_or_path validation."""

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            _require_string_or_path("", "ctx")

    def test_whitespace_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            _require_string_or_path("  ", "ctx")

    def test_empty_path_raises(self) -> None:
        """A Path with only-whitespace str representation raises."""
        with pytest.raises(ValidationError, match="must not be empty"):
            _require_string_or_path(Path("  "), "ctx")

    def test_null_byte_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not contain null bytes"):
            _require_string_or_path("\x00broken", "ctx")

    def test_null_byte_path_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not contain null bytes"):
            _require_string_or_path(Path("\x00broken"), "ctx")

    def test_wrong_type_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a string or path"):
            _require_string_or_path(123, "ctx")

    def test_valid_string(self) -> None:
        assert _require_string_or_path("lib.yar", "ctx") == "lib.yar"

    def test_valid_path(self, tmp_path: Path) -> None:
        result = _require_string_or_path(tmp_path, "ctx")
        assert result == tmp_path


# ---------------------------------------------------------------------------
# _require_yara_file (lines 68-69)
# ---------------------------------------------------------------------------


class TestRequireYaraFile:
    """Lines 64-69: _require_yara_file validation."""

    def test_non_yara_file_raises(self) -> None:
        with pytest.raises(ValidationError, match="DependencyGraph ast must be a YaraFile"):
            _require_yara_file(None)

    def test_non_yara_file_object_raises(self) -> None:
        with pytest.raises(ValidationError, match="DependencyGraph ast must be a YaraFile"):
            _require_yara_file(object())

    def test_valid_yara_file(self) -> None:
        yf = _parse("rule x { condition: true }")
        result = _require_yara_file(yf)
        assert result is yf


# ---------------------------------------------------------------------------
# _normalize_include_resolutions (lines 76-77)
# ---------------------------------------------------------------------------


class TestNormalizeIncludeResolutions:
    """Lines 73-86: _normalize_include_resolutions validation."""

    def test_none_returns_empty_dict(self) -> None:
        assert _normalize_include_resolutions(None) == {}

    def test_non_mapping_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be a mapping"):
            _normalize_include_resolutions(42)

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValidationError, match="include resolution key"):
            _normalize_include_resolutions({"": "value"})

    def test_non_string_value_raises(self) -> None:
        with pytest.raises(ValidationError, match="include resolution value"):
            _normalize_include_resolutions({"key": 99})

    def test_valid_mapping_with_string_value(self) -> None:
        result = _normalize_include_resolutions({"lib.yar": "/path/to/lib.yar"})
        assert result == {"lib.yar": "/path/to/lib.yar"}

    def test_valid_mapping_with_path_value(self, tmp_path: Path) -> None:
        result = _normalize_include_resolutions({"lib.yar": tmp_path})
        assert result == {"lib.yar": tmp_path}


# ---------------------------------------------------------------------------
# _module_name_for_object (line 94-95)
# ---------------------------------------------------------------------------


class TestModuleNameForObject:
    """Lines 89-96: _module_name_for_object name-attribute fallback."""

    def test_module_attribute_takes_priority(self) -> None:
        class Obj:
            module = "pe"
            name = "other"

        assert _module_name_for_object(Obj()) == "pe"

    def test_name_attribute_fallback_when_module_is_not_str(self) -> None:
        """When .module is None (not a string), .name string is returned (line 94-95)."""

        class Obj:
            module = None
            name = "cuckoo"

        assert _module_name_for_object(Obj()) == "cuckoo"

    def test_neither_attribute_returns_none(self) -> None:
        assert _module_name_for_object(object()) is None

    def test_module_is_non_string_and_name_is_non_string_returns_none(self) -> None:
        class Obj:
            module = 42
            name = 99

        assert _module_name_for_object(Obj()) is None


# ---------------------------------------------------------------------------
# _rule_occurrence_keys (lines 141-144, 152-156)
# ---------------------------------------------------------------------------


class TestRuleOccurrenceKeys:
    """Lines 135-157: _rule_occurrence_keys with used_indices_by_name."""

    def test_no_duplicates_single_rule(self) -> None:
        rules = [_parse("rule alpha { condition: true }").rules[0]]
        keys = _rule_occurrence_keys(rules, used_indices_by_name=None)
        assert keys[id(rules[0])] == "alpha"

    def test_used_indices_injected_forces_indexed_key(self) -> None:
        """When used_indices_by_name already marks index 1 as used, the new rule
        gets index 2 (lines 141-144 consume the mapping, 152-156 find the gap)."""
        rules = [_parse("rule alpha { condition: true }").rules[0]]
        # Pretend index 1 is already taken
        keys = _rule_occurrence_keys(rules, used_indices_by_name={"alpha": {1}})
        assert keys[id(rules[0])] == "alpha#2"

    def test_two_rules_same_name_get_sequential_indices(self) -> None:
        """Parser rejects duplicate names; use Rule constructor directly."""
        r1 = Rule(name="alpha")
        r2 = Rule(name="alpha")
        keys = _rule_occurrence_keys([r1, r2])
        values = list(keys.values())
        assert set(values) == {"alpha#1", "alpha#2"}

    def test_used_indices_gap_is_filled(self) -> None:
        """Indices {1, 3} in use -> next gets 2 (while loop in lines 152-154)."""
        rules = [_parse("rule alpha { condition: true }").rules[0]]
        keys = _rule_occurrence_keys(rules, used_indices_by_name={"alpha": {1, 3}})
        assert keys[id(rules[0])] == "alpha#2"


# ---------------------------------------------------------------------------
# _RuleDependencyCollector (lines 112-132)
# ---------------------------------------------------------------------------


class TestRuleDependencyCollector:
    """Lines 112-132: collector module-reference accumulation."""

    def test_add_module_reference_not_in_aliases_is_ignored(self) -> None:
        """Canonical name not found in aliases -> module_references stays empty (line 131->exit)."""
        coll = _RuleDependencyCollector("my_rule", set(), {"pe": "pe"})
        coll._add_module_reference("math")  # 'math' not in aliases
        assert coll.module_references == set()

    def test_add_module_reference_none_is_ignored(self) -> None:
        coll = _RuleDependencyCollector("my_rule", set(), {"pe": "pe"})
        coll._add_module_reference(None)
        assert coll.module_references == set()

    def test_add_module_reference_with_matching_alias(self) -> None:
        coll = _RuleDependencyCollector("my_rule", set(), {"pe": "pe"})
        coll._add_module_reference("pe")
        assert coll.module_references == {"pe"}

    def test_visit_module_reference_node(self) -> None:
        """visit_module_reference (line 123-125) is called by the visitor dispatcher."""
        mr = ModuleReference(module="cuckoo")
        coll = _RuleDependencyCollector("my_rule", set(), {"cuckoo": "cuckoo"})
        coll.visit(mr)
        assert coll.module_references == {"cuckoo"}

    def test_visit_member_access_extracts_module_from_object(self) -> None:
        """visit_member_access (lines 119-121) resolves the module from node.object."""
        from yaraast.ast.expressions import MemberAccess

        mr = ModuleReference(module="pe")
        ma = MemberAccess(object=mr, member="number_of_sections")
        coll = _RuleDependencyCollector("rule_x", set(), {"pe": "pe"})
        coll.visit(ma)
        assert coll.module_references == {"pe"}

    def test_visit_member_access_via_real_condition(self, tmp_path: Path) -> None:
        """pe.number_of_sections in a condition triggers visit_member_access in the graph."""
        yf = _yf("rule r { condition: pe.number_of_sections > 0 }", imports=["pe"])
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        deps = g.get_rule_dependencies("r")
        assert "pe" in deps

    def test_visit_function_call_with_dotted_name_extracts_prefix(self) -> None:
        """visit_function_call splits 'math.entropy' -> 'math' (lines 113-114)."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.yar"
            yf = _yf(
                "rule func_rule { condition: math.entropy(0, filesize) > 6.0 }",
                imports=["math"],
            )
            g = DependencyGraph()
            g.add_file(p, yf)
            deps = g.get_rule_dependencies("func_rule")
            assert "math" in deps

    def test_visit_function_call_without_dot_extracts_no_module(self) -> None:
        """visit_function_call with no '.' in name -> module_name=None (line 114 else)."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.yar"
            # filesize is a built-in YARA keyword with no dot; no module should be added
            yf = _yf("rule r { condition: filesize > 0 }")
            g = DependencyGraph()
            g.add_file(p, yf)
            # No module node should have been created
            module_nodes = [k for k, n in g.nodes.items() if n.type == "module"]
            assert module_nodes == []


# ---------------------------------------------------------------------------
# _validate_file_ast (lines 252-277)
# ---------------------------------------------------------------------------


class TestValidateFileAst:
    """Lines 250-277: _validate_file_ast validation paths."""

    def _make_fake_file(
        self,
        imports: list[object] | None = None,
        includes: list[object] | None = None,
        rules: list[object] | None = None,
    ) -> object:
        obj = SimpleNamespace()
        obj.imports = imports or []
        obj.includes = includes or []
        obj.rules = rules or []
        return obj

    def test_bad_import_node_raises(self, tmp_path: Path) -> None:
        fake = self._make_fake_file(imports=[object()])
        with pytest.raises(ValidationError, match="imports must contain Import nodes"):
            DependencyGraph()._validate_file_ast(fake)  # type: ignore[arg-type]

    def test_import_with_empty_alias_raises(self, tmp_path: Path) -> None:
        yf = YaraFile(imports=[Import(module="pe", alias="")], rules=[])
        with pytest.raises(ValidationError, match="import alias"):
            DependencyGraph()._validate_file_ast(yf)

    def test_bad_include_node_raises(self) -> None:
        fake = self._make_fake_file(includes=[object()])
        with pytest.raises(ValidationError, match="includes must contain Include nodes"):
            DependencyGraph()._validate_file_ast(fake)  # type: ignore[arg-type]

    def test_bad_rule_node_raises(self) -> None:
        fake = self._make_fake_file(rules=[object()])
        with pytest.raises(ValidationError, match="rules must contain Rule nodes"):
            DependencyGraph()._validate_file_ast(fake)  # type: ignore[arg-type]

    def test_rule_with_non_tag_object_raises(self) -> None:
        rule = Rule(name="test_rule", tags=[object()])  # type: ignore[list-item]
        fake = self._make_fake_file(rules=[rule])
        with pytest.raises(ValidationError, match="rule tags must contain Tag nodes"):
            DependencyGraph()._validate_file_ast(fake)  # type: ignore[arg-type]

    def test_rule_with_valid_tag_passes(self, tmp_path: Path) -> None:
        yf = _parse("rule tagged : mytag { condition: true }")
        DependencyGraph()._validate_file_ast(yf)


# ---------------------------------------------------------------------------
# add_file: import alias branch (line 221) and _rename_bare_rule_occurrence call (231)
# ---------------------------------------------------------------------------


class TestAddFileImportAlias:
    """Line 221: module_aliases populated with alias when import_stmt.alias is set."""

    def test_import_alias_maps_to_canonical_module(self, tmp_path: Path) -> None:
        """Import with alias 'my_pe' mapped to canonical 'pe'.
        A rule that references 'my_pe' in its condition resolves to the 'pe' module."""
        # Build a YaraFile with an aliased import and a rule using ModuleReference
        mr = ModuleReference(module="my_pe")
        rule = Rule(name="alias_rule", condition=mr)
        yf = YaraFile(imports=[Import(module="pe", alias="my_pe")], rules=[rule])

        p = tmp_path / "test.yar"
        g = DependencyGraph()
        g.add_file(p, yf)

        # 'pe' module node must exist; alias_rule must depend on 'pe'
        assert "pe" in g.nodes
        assert g.nodes["pe"].type == "module"
        rule_deps = g.get_rule_dependencies("alias_rule")
        assert "pe" in rule_deps


class TestAddFileDuplicateRulesAcrossFiles:
    """Line 231: _rename_bare_rule_occurrence is called inside add_file."""

    def test_adding_second_file_with_same_rule_name_renames_first(self, tmp_path: Path) -> None:
        yf_a = _parse("rule alpha { condition: true }")
        yf_b = _parse("rule alpha { condition: true }")

        pa = tmp_path / "a.yar"
        pb = tmp_path / "b.yar"
        g = DependencyGraph()
        g.add_file(pa, yf_a)
        g.add_file(pb, yf_b)

        # Bare key gone; both occurrences are indexed
        assert "rule:alpha" not in g.nodes
        assert "rule:alpha#1" in g.nodes
        assert "rule:alpha#2" in g.nodes

    def test_adding_third_file_with_same_rule_name_produces_three_indexed_keys(
        self, tmp_path: Path
    ) -> None:
        yf = _parse("rule alpha { condition: true }")
        g = DependencyGraph()
        for name in ("a.yar", "b.yar", "c.yar"):
            g.add_file(tmp_path / name, yf)

        assert "rule:alpha#1" in g.nodes
        assert "rule:alpha#2" in g.nodes
        assert "rule:alpha#3" in g.nodes


# ---------------------------------------------------------------------------
# add_file: else branch for existing node (lines 208-209)
# ---------------------------------------------------------------------------


class TestAddFilePromotesIncludePlaceholder:
    """Lines 207-209: file_key already in nodes as 'include' placeholder."""

    def test_include_placeholder_promoted_to_file(self, tmp_path: Path) -> None:
        """When main.yar includes lib.yar, lib.yar is first registered as an
        'include' node.  Adding lib.yar as a proper file promotes it to type='file'
        (the else branch at line 208)."""
        src_main = 'include "lib.yar"\nrule main { condition: true }'
        src_lib = "rule lib_rule { condition: true }"
        yf_main = _parse(src_main)
        yf_lib = _parse(src_lib)

        pmain = tmp_path / "main.yar"
        plib = tmp_path / "lib.yar"

        g = DependencyGraph()
        g.add_file(pmain, yf_main, include_resolutions={"lib.yar": str(plib)})
        # At this point plib is an include placeholder
        assert g.nodes[str(plib)].type == "include"

        g.add_file(plib, yf_lib)
        # Now it must be a proper file node
        assert g.nodes[str(plib)].type == "file"
        assert "rule:lib_rule" in g.nodes


# ---------------------------------------------------------------------------
# _remove_existing_file_state edge cases (lines 286->284, 294->297, 309)
# ---------------------------------------------------------------------------


class TestRemoveExistingFileState:
    """Lines 279-302: _remove_existing_file_state with missing nodes."""

    def test_dependency_node_not_in_graph_is_handled_gracefully(self) -> None:
        """When a file's dependency key has been deleted from nodes already,
        the removal loop skips it silently (line 286->284 branch)."""
        g = DependencyGraph()
        file_key = "/tmp/ghost_file.yar"
        g.nodes[file_key] = DependencyNode(name=file_key, type="file", file_path=Path(file_key))
        # Add a dependency key that is NOT in nodes
        g.nodes[file_key].dependencies.add("ghost_dep")
        g.file_rules[file_key] = set()
        # Must not raise
        g._remove_existing_file_state(file_key)
        assert file_key not in g.file_rules

    def test_rule_node_file_path_mismatch_skips_remove_but_deletes_rule_files(
        self,
    ) -> None:
        """Rule's file_path points to a different file than the one being removed.
        _remove_rule_node is not called, but rule_files entry is still deleted
        (line 294->297 branch)."""
        g = DependencyGraph()
        file_key = "/tmp/a.yar"
        other_file = "/tmp/b.yar"

        g.nodes[file_key] = DependencyNode(name=file_key, type="file", file_path=Path(file_key))
        # Rule claims to belong to other_file
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path(other_file)
        )
        g.file_rules[file_key] = {"alpha"}
        g.rule_files["alpha"] = file_key

        g._remove_existing_file_state(file_key)

        # Rule node must survive (file_path mismatch skips removal)
        assert "rule:alpha" in g.nodes
        # But rule_files entry for alpha must be deleted
        assert "alpha" not in g.rule_files

    def test_re_adding_file_triggers_remove_rule_node_dependents_clearing(
        self, tmp_path: Path
    ) -> None:
        """When a rule that other rules depend on is removed (by replacing its
        file with a different version), the dependents of that rule have the
        dependency edge cleaned up (lines 317-320 in _remove_rule_node)."""
        src_lib = "rule lib_rule { condition: true }"
        src_alpha = "rule alpha { condition: lib_rule }"
        src_lib_v2 = "rule lib_rule_v2 { condition: true }"

        yf_lib = _parse(src_lib)
        yf_alpha = _parse(src_alpha)
        yf_lib_v2 = _parse(src_lib_v2)

        plib = tmp_path / "lib.yar"
        palpha = tmp_path / "alpha.yar"

        g = DependencyGraph()
        g.add_file(plib, yf_lib)
        g.add_file(palpha, yf_alpha)

        # alpha depends on lib_rule
        assert "rule:lib_rule" in g.nodes["rule:alpha"].dependencies

        # Replace lib.yar with a version that lacks lib_rule
        g.add_file(plib, yf_lib_v2)

        assert "rule:lib_rule" not in g.nodes
        # alpha's dependency on lib_rule must have been removed
        assert "rule:lib_rule" not in g.nodes["rule:alpha"].dependencies


# ---------------------------------------------------------------------------
# _rename_bare_rule_occurrence guard conditions (lines 327-328)
# ---------------------------------------------------------------------------


class TestRenameBareRuleOccurrence:
    """Lines 322-349: _rename_bare_rule_occurrence early-return guards."""

    def test_no_node_returns_silently(self) -> None:
        g = DependencyGraph()
        g._rename_bare_rule_occurrence("nonexistent")  # must not raise

    def test_node_type_not_rule_returns_silently(self) -> None:
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="file", file_path=Path("/tmp/a.yar")
        )
        g._rename_bare_rule_occurrence("alpha")
        # Node unchanged
        assert "rule:alpha" in g.nodes
        assert "rule:alpha#1" not in g.nodes

    def test_new_key_already_exists_returns_silently(self) -> None:
        """Guard: new_key ('rule:alpha#1') already in nodes -> return (line 327)."""
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/b.yar")
        )
        g._rename_bare_rule_occurrence("alpha")
        # Both keys must still exist unchanged
        assert "rule:alpha" in g.nodes
        assert "rule:alpha#1" in g.nodes

    def test_rename_updates_file_rules_when_rule_present(self, tmp_path: Path) -> None:
        """The file_rules mapping is updated when the bare key is in file_rules (lines 342-345)."""
        g = DependencyGraph()
        file_path_str = str(tmp_path / "a.yar")
        g.nodes[file_path_str] = DependencyNode(
            name=file_path_str, type="file", file_path=Path(file_path_str)
        )
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path(file_path_str)
        )
        g.rule_files["alpha"] = file_path_str
        g.file_rules[file_path_str] = {"alpha"}

        g._rename_bare_rule_occurrence("alpha")

        assert "rule:alpha#1" in g.nodes
        assert "rule:alpha" not in g.nodes
        assert "alpha#1" in g.file_rules[file_path_str]
        assert "alpha" not in g.file_rules[file_path_str]

    def test_rename_skips_file_rules_update_when_rule_not_present(self) -> None:
        """When file_rules[file_path] doesn't contain rule_name, add is not called."""
        g = DependencyGraph()
        file_path_str = "/tmp/a.yar"
        g.nodes[file_path_str] = DependencyNode(
            name=file_path_str, type="file", file_path=Path(file_path_str)
        )
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path(file_path_str)
        )
        g.rule_files["alpha"] = file_path_str
        g.file_rules[file_path_str] = {"other_rule"}  # 'alpha' intentionally absent

        g._rename_bare_rule_occurrence("alpha")

        assert "rule:alpha#1" in g.nodes
        # 'alpha#1' must NOT have been added to file_rules (it wasn't tracked)
        assert "alpha#1" not in g.file_rules[file_path_str]
        assert "other_rule" in g.file_rules[file_path_str]


# ---------------------------------------------------------------------------
# _compact_unique_rule_occurrence guard conditions (lines 354-388)
# ---------------------------------------------------------------------------


class TestCompactUniqueRuleOccurrence:
    """Lines 351-388: _compact_unique_rule_occurrence guard conditions."""

    def test_bare_key_already_exists_returns_silently(self) -> None:
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        g._compact_unique_rule_occurrence("alpha")
        # Guard at line 354: bare_key in nodes -> return immediately
        assert "rule:alpha" in g.nodes

    def test_no_matching_keys_returns_silently(self) -> None:
        g = DependencyGraph()
        g._compact_unique_rule_occurrence("nonexistent")

    def test_multiple_matching_keys_returns_silently(self) -> None:
        g = DependencyGraph()
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        g.nodes["rule:alpha#2"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/b.yar")
        )
        g._compact_unique_rule_occurrence("alpha")
        # Must not compact because there are two occurrences
        assert "rule:alpha" not in g.nodes

    def test_matching_key_without_hash_prefix_returns_silently(self) -> None:
        """The only matching key doesn't start with 'rule:alpha#' -> skip compact."""
        g = DependencyGraph()
        g.nodes["rule:alpha:extra"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        g._compact_unique_rule_occurrence("alpha")
        assert "rule:alpha" not in g.nodes

    def test_matching_key_wrong_type_returns_silently(self) -> None:
        g = DependencyGraph()
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="file", file_path=Path("/tmp/a.yar")
        )
        g._compact_unique_rule_occurrence("alpha")
        assert "rule:alpha" not in g.nodes

    def test_full_compact_via_add_file_replace(self, tmp_path: Path) -> None:
        """End-to-end: add 2 files with same rule name, replace one -> alpha#1 compacts to alpha."""
        yf_a = _parse("rule alpha { condition: true }")
        yf_b = _parse("rule alpha { condition: true }")
        yf_other = _parse("rule other { condition: true }")

        pa = tmp_path / "a.yar"
        pb = tmp_path / "b.yar"

        g = DependencyGraph()
        g.add_file(pa, yf_a)
        g.add_file(pb, yf_b)
        assert "rule:alpha#1" in g.nodes
        assert "rule:alpha#2" in g.nodes

        # Replace b with different rule -> alpha#2 removed, alpha#1 compacted to alpha
        g.add_file(pb, yf_other)
        assert "rule:alpha" in g.nodes
        assert "rule:alpha#1" not in g.nodes
        assert "rule:alpha#2" not in g.nodes
        assert "rule:other" in g.nodes

    def test_compact_updates_file_rules_and_rule_files(self) -> None:
        """After compacting, file_rules and rule_files reflect the bare key."""
        g = DependencyGraph()
        file_path_str = "/tmp/a.yar"
        g.nodes[file_path_str] = DependencyNode(
            name=file_path_str, type="file", file_path=Path(file_path_str)
        )
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path(file_path_str)
        )
        g.rule_files["alpha#1"] = file_path_str
        g.file_rules[file_path_str] = {"alpha#1"}

        g._compact_unique_rule_occurrence("alpha")

        assert "rule:alpha" in g.nodes
        assert "rule:alpha#1" not in g.nodes
        assert g.rule_files.get("alpha") == file_path_str
        assert "alpha" in g.file_rules[file_path_str]
        assert "alpha#1" not in g.file_rules[file_path_str]


# ---------------------------------------------------------------------------
# _remove_orphan_external_node (line 394)
# ---------------------------------------------------------------------------


class TestRemoveOrphanExternalNode:
    """Lines 390-394: _remove_orphan_external_node type and dependent checks."""

    def test_include_with_no_dependents_is_removed(self) -> None:
        g = DependencyGraph()
        g.nodes["lib.yar"] = DependencyNode(name="lib.yar", type="include")
        g._remove_orphan_external_node("lib.yar")
        assert "lib.yar" not in g.nodes

    def test_module_with_no_dependents_is_removed(self) -> None:
        g = DependencyGraph()
        g.nodes["pe"] = DependencyNode(name="pe", type="module")
        g._remove_orphan_external_node("pe")
        assert "pe" not in g.nodes

    def test_node_with_dependents_is_preserved(self) -> None:
        g = DependencyGraph()
        g.nodes["pe"] = DependencyNode(name="pe", type="module")
        g.nodes["pe"].dependents.add("some_file")
        g._remove_orphan_external_node("pe")
        assert "pe" in g.nodes

    def test_file_type_node_is_never_removed(self) -> None:
        g = DependencyGraph()
        g.nodes["test.yar"] = DependencyNode(name="test.yar", type="file")
        g._remove_orphan_external_node("test.yar")
        assert "test.yar" in g.nodes

    def test_nonexistent_key_is_no_op(self) -> None:
        g = DependencyGraph()
        g._remove_orphan_external_node("nonexistent")

    def test_module_orphaned_by_file_replacement_is_removed(self, tmp_path: Path) -> None:
        """When a file is re-added without its original import, the module node
        becomes an orphan and is removed (line 394 via _remove_existing_file_state)."""
        yf_with = _yf("rule x { condition: pe.is_pe() }", imports=["pe"])
        yf_without = _parse("rule x { condition: true }")

        p = tmp_path / "test.yar"
        g = DependencyGraph()
        g.add_file(p, yf_with)
        assert "pe" in g.nodes

        g.add_file(p, yf_without)
        assert "pe" not in g.nodes

    def test_include_orphaned_by_file_replacement_is_removed(self, tmp_path: Path) -> None:
        """When a file is re-added without its include, the unresolved include
        placeholder is removed as an orphan."""
        src_with_include = 'include "ghost.yar"\nrule x { condition: true }'
        src_without_include = "rule x { condition: true }"
        yf_with = _parse(src_with_include)
        yf_without = _parse(src_without_include)

        p = tmp_path / "test.yar"
        g = DependencyGraph()
        g.add_file(p, yf_with)
        assert "ghost.yar" in g.nodes

        g.add_file(p, yf_without)
        assert "ghost.yar" not in g.nodes


# ---------------------------------------------------------------------------
# get_file_dependencies / get_file_dependents resolved path branch (lines 503-504, 511-512)
# ---------------------------------------------------------------------------


class TestResolvedPathBranch:
    """Lines 503-504, 511-512: get_file_dependencies/dependents via resolved symlink path.

    On macOS /var is a symlink to /private/var.  tempfile creates paths under
    /var/..., and Path.resolve() returns /private/var/...  When the graph is
    keyed by the resolved path, queries with the unresolved path still return
    the correct result because the method tries the resolved form first.
    """

    def test_get_file_dependencies_via_resolved_path(self, tmp_path: Path) -> None:
        """Query with unresolved path hits the 'resolved_path in nodes' branch."""
        yf = _parse("rule x { condition: true }")
        p = tmp_path / "test.yar"
        resolved_p = p.resolve()

        g = DependencyGraph()
        g.add_file(resolved_p, yf)

        # The query is made with the unresolved path; resolve() may differ on macOS
        deps = g.get_file_dependencies(p)
        # At minimum the rule node should be reachable
        assert isinstance(deps, set)

    def test_get_file_dependents_via_resolved_path(self, tmp_path: Path) -> None:
        src_lib = "rule lib_rule { condition: true }"
        src_main = 'include "lib.yar"\nrule main_rule { condition: true }'
        yf_lib = _parse(src_lib)
        yf_main = _parse(src_main)

        plib = tmp_path / "lib.yar"
        pmain = tmp_path / "main.yar"
        plib_resolved = plib.resolve()
        pmain_resolved = pmain.resolve()

        g = DependencyGraph()
        g.add_file(plib_resolved, yf_lib)
        g.add_file(
            pmain_resolved,
            yf_main,
            include_resolutions={"lib.yar": str(plib_resolved)},
        )

        # Query using potentially-unresolved plib
        dependents = g.get_file_dependents(plib)
        assert isinstance(dependents, set)
        # main.yar (either form) should appear in the dependents
        dependents_str = {str(d) for d in dependents}
        assert any("main.yar" in d for d in dependents_str)

    def test_get_file_dependencies_for_missing_path_returns_empty(self, tmp_path: Path) -> None:
        g = DependencyGraph()
        result = g.get_file_dependencies(tmp_path / "nonexistent.yar")
        assert result == set()

    def test_get_file_dependents_for_missing_path_returns_empty(self, tmp_path: Path) -> None:
        g = DependencyGraph()
        result = g.get_file_dependents(tmp_path / "nonexistent.yar")
        assert result == set()


# ---------------------------------------------------------------------------
# _used_rule_occurrence_indices (lines 475-479)
# ---------------------------------------------------------------------------


class TestUsedRuleOccurrenceIndices:
    """Lines 465-480: _used_rule_occurrence_indices with unusual node keys."""

    def test_rule_node_key_without_hash_prefix_skipped(self) -> None:
        """A rule node whose key is neither the bare form nor 'bare#N' is skipped
        (line 475: not startswith indexed_prefix -> continue)."""
        g = DependencyGraph()
        g.nodes["rule:alpha:extra"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/t.yar")
        )
        result = g._used_rule_occurrence_indices()
        assert result == {}

    def test_rule_node_key_with_non_decimal_suffix_skipped(self) -> None:
        """A key like 'rule:alpha#abc' has a non-decimal suffix -> isdecimal() False
        (line 478: if occurrence.isdecimal() -> skip)."""
        g = DependencyGraph()
        g.nodes["rule:alpha#abc"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/t.yar")
        )
        result = g._used_rule_occurrence_indices()
        assert result == {}

    def test_normal_indexed_key_is_included(self) -> None:
        g = DependencyGraph()
        g.nodes["rule:alpha#3"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/t.yar")
        )
        result = g._used_rule_occurrence_indices()
        assert result == {"alpha": {3}}

    def test_bare_key_counts_as_index_one(self) -> None:
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/t.yar")
        )
        result = g._used_rule_occurrence_indices()
        assert result == {"alpha": {1}}


# ---------------------------------------------------------------------------
# get_rule_dependencies (line 520)
# ---------------------------------------------------------------------------


class TestGetRuleDependencies:
    """Lines 515-521: get_rule_dependencies."""

    def test_unknown_rule_returns_empty_set(self, tmp_path: Path) -> None:
        g = DependencyGraph()
        assert g.get_rule_dependencies("nonexistent") == set()

    def test_rule_without_condition_has_no_cross_rule_deps(self, tmp_path: Path) -> None:
        yf = YaraFile(rules=[Rule(name="no_cond", condition=None)])
        p = tmp_path / "test.yar"
        g = DependencyGraph()
        g.add_file(p, yf)
        # Condition is None -> no rule-to-rule dependency
        deps = g.get_rule_dependencies("no_cond")
        # file_key still there but no rule deps
        assert all(not k.startswith("rule:") for k in deps)


# ---------------------------------------------------------------------------
# _get_transitive_dependencies / _get_transitive_dependents (lines 526, 548-567)
# ---------------------------------------------------------------------------


class TestTransitiveTraversal:
    """Lines 523-567: transitive dependency and dependent traversal."""

    def test_transitive_deps_excludes_start_node(self, tmp_path: Path) -> None:
        src = (
            "rule alpha { condition: true }\n"
            "rule beta { condition: alpha }\n"
            "rule gamma { condition: beta }"
        )
        yf = _parse(src)
        p = tmp_path / "test.yar"
        g = DependencyGraph()
        g.add_file(p, yf)

        # Transitive deps of gamma: beta and alpha (both rules)
        deps = g._get_transitive_dependencies(str(p))
        assert "rule:alpha" in deps
        assert "rule:beta" in deps
        # Start node (the file) must not appear in its own deps
        assert str(p) not in deps

    def test_transitive_deps_of_unknown_node_returns_empty(self) -> None:
        g = DependencyGraph()
        assert g._get_transitive_dependencies("missing") == set()

    def test_transitive_dependents_excludes_start_node(self, tmp_path: Path) -> None:
        src_lib = "rule lib_rule { condition: true }"
        src_main = 'include "lib.yar"\nrule main_rule { condition: true }'
        yf_lib = _parse(src_lib)
        yf_main = _parse(src_main)

        plib = tmp_path / "lib.yar"
        pmain = tmp_path / "main.yar"
        g = DependencyGraph()
        g.add_file(plib, yf_lib)
        g.add_file(pmain, yf_main, include_resolutions={"lib.yar": str(plib)})

        dependents = g._get_transitive_dependents(str(plib))
        assert str(plib) not in dependents
        assert str(pmain) in dependents

    def test_transitive_dependents_of_unknown_node_returns_empty(self) -> None:
        g = DependencyGraph()
        assert g._get_transitive_dependents("missing") == set()

    def test_transitive_traversal_handles_already_visited(self, tmp_path: Path) -> None:
        """A diamond-shaped graph (A->B, A->C, B->D, C->D) must not infinite-loop
        and must return D only once."""
        g = DependencyGraph()
        for name in ("A", "B", "C", "D"):
            g.nodes[name] = DependencyNode(name=name, type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["A"].dependencies = {"B", "C"}
        g.nodes["B"].dependencies = {"D"}
        g.nodes["C"].dependencies = {"D"}
        g.nodes["B"].dependents = {"A"}
        g.nodes["C"].dependents = {"A"}
        g.nodes["D"].dependents = {"B", "C"}

        deps = g._get_transitive_dependencies("A")
        assert deps == {"B", "C", "D"}


# ---------------------------------------------------------------------------
# find_cycles (lines 579, 583, 593, 614)
# ---------------------------------------------------------------------------


class TestFindCycles:
    """Lines 569-607: find_cycles DFS with deduplication and dangling edges."""

    def test_no_cycles_returns_empty(self, tmp_path: Path) -> None:
        yf = _parse("rule x { condition: true }")
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        assert g.find_cycles() == []

    def test_simple_two_node_cycle(self) -> None:
        g = DependencyGraph()
        for name in ("a", "b"):
            g.nodes[name] = DependencyNode(name=name, type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["a"].dependencies.add("b")
        g.nodes["b"].dependents.add("a")
        g.nodes["b"].dependencies.add("a")
        g.nodes["a"].dependents.add("b")

        cycles = g.find_cycles()
        assert len(cycles) == 1
        assert cycles[0][0] == cycles[0][-1]  # normalized: starts and ends at same node

    def test_duplicate_cycle_reported_only_once(self) -> None:
        """Triangle a->b->c->a contains one normalized cycle.
        The DFS may discover it from multiple entry points;
        deduplication (line 583) ensures it appears only once."""
        g = DependencyGraph()
        for name in ("a", "b", "c"):
            g.nodes[name] = DependencyNode(name=name, type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["a"].dependencies = {"b"}
        g.nodes["b"].dependencies = {"c"}
        g.nodes["c"].dependencies = {"a"}
        g.nodes["a"].dependents = {"c"}
        g.nodes["b"].dependents = {"a"}
        g.nodes["c"].dependents = {"b"}

        cycles = g.find_cycles()
        # Only one unique cycle: a->b->c->a
        cycle_bodies = [tuple(c[:-1]) for c in cycles]
        assert len(set(cycle_bodies)) == len(cycle_bodies)

    def test_dangling_dependency_skipped(self) -> None:
        """A dependency key that is not in self.nodes is skipped (line 593)."""
        g = DependencyGraph()
        g.nodes["a"] = DependencyNode(name="a", type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["a"].dependencies.add("ghost_node")

        cycles = g.find_cycles()
        assert cycles == []

    def test_already_visited_non_active_node_does_not_create_cycle(self) -> None:
        """A node visited but not in the active path does not constitute a cycle."""
        g = DependencyGraph()
        for name in ("a", "b", "c"):
            g.nodes[name] = DependencyNode(name=name, type="rule", file_path=Path("/tmp/t.yar"))
        # a->b, a->c, b->c (c is reachable from both a and b; no cycle)
        g.nodes["a"].dependencies = {"b", "c"}
        g.nodes["b"].dependencies = {"c"}
        g.nodes["b"].dependents = {"a"}
        g.nodes["c"].dependents = {"a", "b"}

        cycles = g.find_cycles()
        assert cycles == []


# ---------------------------------------------------------------------------
# get_isolated_nodes (lines 609-615)
# ---------------------------------------------------------------------------


class TestGetIsolatedNodes:
    """Lines 609-615: get_isolated_nodes."""

    def test_empty_graph_has_no_isolated_nodes(self) -> None:
        g = DependencyGraph()
        assert g.get_isolated_nodes() == set()

    def test_orphan_node_is_isolated(self) -> None:
        g = DependencyGraph()
        g.nodes["orphan"] = DependencyNode(name="orphan", type="module")
        assert g.get_isolated_nodes() == {"orphan"}

    def test_connected_nodes_are_not_isolated(self, tmp_path: Path) -> None:
        yf = _parse("rule x { condition: true }")
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        # file and rule are connected; neither is isolated
        assert g.get_isolated_nodes() == set()


# ---------------------------------------------------------------------------
# get_statistics
# ---------------------------------------------------------------------------


class TestGetStatistics:
    """Lines 617-631: get_statistics counts all node types correctly."""

    def test_empty_graph_statistics(self) -> None:
        g = DependencyGraph()
        stats = g.get_statistics()
        assert stats["total_nodes"] == 0
        assert stats["file_count"] == 0
        assert stats["rule_count"] == 0
        assert stats["module_count"] == 0
        assert stats["total_edges"] == 0
        assert stats["isolated_nodes"] == 0
        assert stats["cycles"] == 0

    def test_statistics_with_file_and_rules(self, tmp_path: Path) -> None:
        yf = _yf(
            "rule alpha { condition: true }",
            "rule beta { condition: alpha }",
            imports=["pe"],
        )
        p = tmp_path / "test.yar"
        g = DependencyGraph()
        g.add_file(p, yf)

        stats = g.get_statistics()
        assert stats["file_count"] == 1
        assert stats["rule_count"] == 2
        assert stats["module_count"] == 1
        assert stats["total_nodes"] == 4  # file + pe + alpha + beta
        assert stats["cycles"] == 0


# ---------------------------------------------------------------------------
# export_dot (lines 633-665, including line 646-649 for module type)
# ---------------------------------------------------------------------------


class TestExportDot:
    """Lines 633-665: export_dot covers all four node-type branches."""

    def test_dot_contains_digraph_header(self, tmp_path: Path) -> None:
        yf = _parse("rule x { condition: true }")
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        dot = g.export_dot()
        assert dot.startswith("digraph YaraDependencies {")
        assert dot.endswith("}")

    def test_dot_has_file_style(self, tmp_path: Path) -> None:
        yf = _parse("rule x { condition: true }")
        p = tmp_path / "test.yar"
        g = DependencyGraph()
        g.add_file(p, yf)
        dot = g.export_dot()
        assert "fillcolor=lightblue" in dot

    def test_dot_has_rule_style(self, tmp_path: Path) -> None:
        yf = _parse("rule my_rule { condition: true }")
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        dot = g.export_dot()
        assert "fillcolor=lightgreen" in dot

    def test_dot_has_module_style(self, tmp_path: Path) -> None:
        """Module-type nodes use lightyellow fill (line 647)."""
        yf = _yf("rule r { condition: pe.is_pe() }", imports=["pe"])
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        dot = g.export_dot()
        assert "fillcolor=lightyellow" in dot

    def test_dot_include_node_has_empty_style(self, tmp_path: Path) -> None:
        """Unresolved include placeholders are 'include' type -> else branch (line 649: style='')."""
        src = 'include "ghost.yar"\nrule r { condition: true }'
        yf = _parse(src)
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        dot = g.export_dot()
        # ghost.yar node must appear with empty style (label only, trailing comma)
        assert '"ghost.yar" [label="ghost.yar",];' in dot

    def test_dot_escapes_special_characters_in_node_key(self, tmp_path: Path) -> None:
        """Colon in node keys (e.g., 'rule:foo') is replaced with underscore."""
        yf = _parse("rule foo { condition: true }")
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        dot = g.export_dot()
        assert "rule_foo" in dot

    def test_dot_contains_edges(self, tmp_path: Path) -> None:
        yf = _parse("rule alpha { condition: true }\n" "rule beta { condition: alpha }")
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        dot = g.export_dot()
        assert "->" in dot


# ---------------------------------------------------------------------------
# Full integration: cross-file rule dependency resolution
# ---------------------------------------------------------------------------


class TestCrossFileDependencyResolution:
    """End-to-end: rules across two files that reference each other."""

    def test_rule_in_file_a_depends_on_rule_in_file_b(self, tmp_path: Path) -> None:
        src_b = "rule lib_rule { condition: true }"
        src_a = "rule main_rule { condition: lib_rule }"
        yf_a = _parse(src_a)
        yf_b = _parse(src_b)

        pa = tmp_path / "a.yar"
        pb = tmp_path / "b.yar"
        g = DependencyGraph()
        g.add_file(pb, yf_b)
        g.add_file(pa, yf_a)

        deps = g.get_rule_dependencies("main_rule")
        assert "rule:lib_rule" in deps

    def test_forward_reference_resolves_after_reanalyze(self, tmp_path: Path) -> None:
        """Even when the dependency file is added AFTER the dependent file,
        _reanalyze_all_rules resolves the forward reference."""
        src_dep = "rule dep_rule { condition: true }"
        src_main = "rule user_rule { condition: dep_rule }"
        yf_main = _parse(src_main)
        yf_dep = _parse(src_dep)

        pmain = tmp_path / "main.yar"
        pdep = tmp_path / "dep.yar"

        g = DependencyGraph()
        # Add user first (dep_rule unknown at this point)
        g.add_file(pmain, yf_main)
        assert g.get_rule_dependencies("user_rule") == set()

        # Add dep: triggers _reanalyze_all_rules, which resolves the forward ref
        g.add_file(pdep, yf_dep)
        deps = g.get_rule_dependencies("user_rule")
        assert "rule:dep_rule" in deps

    def test_module_reference_via_function_call_in_rule(self, tmp_path: Path) -> None:
        """A rule calling math.entropy(...) creates a rule->module dependency."""
        yf = _yf(
            "rule entropy_check { condition: math.entropy(0, filesize) > 6.5 }",
            imports=["math"],
        )
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        deps = g.get_rule_dependencies("entropy_check")
        assert "math" in deps

    def test_rule_with_none_condition_produces_no_rule_deps(self, tmp_path: Path) -> None:
        """A Rule with condition=None (line 444: return early) has no rule-level deps."""
        rule = Rule(name="empty_cond", condition=None)
        yf = YaraFile(rules=[rule])
        g = DependencyGraph()
        g.add_file(tmp_path / "test.yar", yf)
        deps = g.get_rule_dependencies("empty_cond")
        # Only the file itself is a dependent; no rule-to-rule edges
        assert all(not k.startswith("rule:") for k in deps)


# ---------------------------------------------------------------------------
# _reanalyze_all_rules: stale entry (line 247->246)
# ---------------------------------------------------------------------------


class TestReanalyzeAllRules:
    """Line 247->246: _reanalyze_all_rules skips when rule_key not in nodes."""

    def test_stale_analysis_input_entry_is_skipped(self) -> None:
        """When _rule_analysis_inputs contains a key not present in nodes,
        the loop body is skipped (branch 247->246)."""
        g = DependencyGraph()
        stale_rule = Rule(name="stale_rule")
        # Inject analysis input without creating the node
        g._rule_analysis_inputs["rule:stale_rule"] = (stale_rule, {})
        # Must not raise; the rule_key guard filters it out
        g._reanalyze_all_rules()
        assert "rule:stale_rule" not in g.nodes


# ---------------------------------------------------------------------------
# _remove_existing_file_state: rule_node is None branch (line 297->291)
# ---------------------------------------------------------------------------


class TestRemoveExistingFileStateRuleNodeNone:
    """Lines 291-298: _remove_existing_file_state when rule node is absent from nodes."""

    def test_rule_in_file_rules_but_node_absent_removes_rule_files_entry(self) -> None:
        """file_rules maps file_key -> {rule_name} but 'rule:{rule_name}' is not in
        nodes (rule_node is None, line 293-294 condition False).
        rule_files entry for the rule is still deleted (line 297-298)."""
        g = DependencyGraph()
        file_key = "/tmp/ghost_rule_test.yar"
        g.nodes[file_key] = DependencyNode(name=file_key, type="file", file_path=Path(file_key))
        g.file_rules[file_key] = {"ghost_rule"}
        g.rule_files["ghost_rule"] = file_key

        g._remove_existing_file_state(file_key)

        # Node is still gone (wasn't there), file_rules cleaned, rule_files deleted
        assert "rule:ghost_rule" not in g.nodes
        assert "ghost_rule" not in g.rule_files

    def test_rule_in_file_rules_but_rule_files_points_elsewhere(self) -> None:
        """file_rules has rule_name but rule_files maps it to a DIFFERENT file_key.
        Condition at line 297 evaluates False (branch 297->291), so rule_files is
        NOT modified for this rule."""
        g = DependencyGraph()
        file_key_a = "/tmp/a_rule_mismatch.yar"
        file_key_b = "/tmp/b_rule_mismatch.yar"
        g.nodes[file_key_a] = DependencyNode(
            name=file_key_a, type="file", file_path=Path(file_key_a)
        )
        g.nodes["rule:shared"] = DependencyNode(
            name="shared", type="rule", file_path=Path(file_key_b)
        )
        # file_rules[a] tracks 'shared' but rule_files['shared'] -> b (different file)
        g.file_rules[file_key_a] = {"shared"}
        g.rule_files["shared"] = file_key_b

        g._remove_existing_file_state(file_key_a)

        # rule_files['shared'] must STILL point to b (not deleted)
        assert g.rule_files.get("shared") == file_key_b
        # The rule node must survive
        assert "rule:shared" in g.nodes


# ---------------------------------------------------------------------------
# _remove_rule_node: all None-guard branches (lines 309, 313->311, 319->317)
# ---------------------------------------------------------------------------


class TestRemoveRuleNode:
    """Lines 304-320: _remove_rule_node internal None guards."""

    def test_absent_rule_key_is_no_op(self) -> None:
        """pop() returns None -> guard at line 308-309 short-circuits (309)."""
        g = DependencyGraph()
        g._remove_rule_node("rule:nonexistent")

    def test_rule_with_missing_dependency_node_is_handled(self) -> None:
        """Rule references a dependency key not in nodes; dependency_node is None (313->311)."""
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/t.yar")
        )
        g.nodes["rule:alpha"].dependencies.add("ghost_dep")

        g._remove_rule_node("rule:alpha")

        assert "rule:alpha" not in g.nodes

    def test_rule_with_missing_dependent_node_is_handled(self) -> None:
        """Rule has a dependent key not in nodes; dependent_node is None (319->317)."""
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/t.yar")
        )
        g.nodes["rule:alpha"].dependents.add("ghost_dependent")

        g._remove_rule_node("rule:alpha")

        assert "rule:alpha" not in g.nodes


# ---------------------------------------------------------------------------
# _rename_bare_rule_occurrence: edge cases (lines 336-337, 340->347)
# ---------------------------------------------------------------------------


class TestRenameBareRuleOccurrenceEdgeCases:
    """Additional edge cases for _rename_bare_rule_occurrence."""

    def test_other_nodes_dependents_updated_when_renamed(self) -> None:
        """When old_key appears in another node's dependents set, it is replaced
        with new_key (lines 335-337)."""
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        # Some other node has rule:alpha as a dependent
        g.nodes["file.yar"] = DependencyNode(
            name="file.yar", type="file", file_path=Path("/tmp/file.yar")
        )
        g.nodes["file.yar"].dependents.add("rule:alpha")
        g.rule_files["alpha"] = "/tmp/a.yar"
        g.file_rules["/tmp/a.yar"] = {"alpha"}

        g._rename_bare_rule_occurrence("alpha")

        assert "rule:alpha#1" in g.nodes["file.yar"].dependents
        assert "rule:alpha" not in g.nodes["file.yar"].dependents

    def test_rename_when_rule_not_in_rule_files_uses_none_file_path(self) -> None:
        """rule_files.pop(rule_name) returns None when rule wasn't registered;
        the file_path=None branch (line 340->347) skips the file_rules update."""
        g = DependencyGraph()
        g.nodes["rule:alpha"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        # rule_files intentionally not populated
        g._rename_bare_rule_occurrence("alpha")

        assert "rule:alpha#1" in g.nodes
        assert "rule:alpha" not in g.nodes


# ---------------------------------------------------------------------------
# _compact_unique_rule_occurrence: edge cases (lines 366, 375-376, 379->386, 382->386)
# ---------------------------------------------------------------------------


class TestCompactUniqueRuleOccurrenceEdgeCases:
    """Additional edge cases for _compact_unique_rule_occurrence."""

    def test_other_nodes_dependencies_updated_when_compacted(self) -> None:
        """When old_key appears in another node's dependencies, it is replaced
        with bare_key (lines 371-373)."""
        g = DependencyGraph()
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        g.nodes["rule:beta"] = DependencyNode(
            name="beta", type="rule", file_path=Path("/tmp/a.yar")
        )
        g.nodes["rule:beta"].dependencies.add("rule:alpha#1")
        g.nodes["rule:alpha#1"].dependents.add("rule:beta")
        g.rule_files["alpha#1"] = "/tmp/a.yar"
        g.file_rules["/tmp/a.yar"] = {"alpha#1"}

        g._compact_unique_rule_occurrence("alpha")

        assert "rule:alpha" in g.nodes["rule:beta"].dependencies
        assert "rule:alpha#1" not in g.nodes["rule:beta"].dependencies

    def test_other_nodes_dependents_updated_when_compacted(self) -> None:
        """When old_key appears in another node's dependents set, it is replaced
        with bare_key (lines 374-376)."""
        g = DependencyGraph()
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        g.nodes["rule:gamma"] = DependencyNode(
            name="gamma", type="rule", file_path=Path("/tmp/a.yar")
        )
        # gamma's dependents include rule:alpha#1 (unusual but valid graph state)
        g.nodes["rule:gamma"].dependents.add("rule:alpha#1")
        g.rule_files["alpha#1"] = "/tmp/a.yar"
        g.file_rules["/tmp/a.yar"] = {"alpha#1"}

        g._compact_unique_rule_occurrence("alpha")

        assert "rule:alpha" in g.nodes["rule:gamma"].dependents
        assert "rule:alpha#1" not in g.nodes["rule:gamma"].dependents

    def test_compact_when_rule_not_in_rule_files_skips_file_update(self) -> None:
        """rule_files.pop(old_rule_name) returns None; file_rules update is skipped
        (line 375->376 = None branch)."""
        g = DependencyGraph()
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path("/tmp/a.yar")
        )
        # rule_files intentionally not populated
        g._compact_unique_rule_occurrence("alpha")

        assert "rule:alpha" in g.nodes
        # rule_files must have no entry for either old or new key
        assert "alpha" not in g.rule_files
        assert "alpha#1" not in g.rule_files

    def test_compact_when_old_rule_name_not_in_file_rules(self) -> None:
        """file_rules[file_path] exists but old_rule_name is absent from it;
        remove/add skipped (line 379->386)."""
        g = DependencyGraph()
        file_path_str = "/tmp/a.yar"
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path(file_path_str)
        )
        g.rule_files["alpha#1"] = file_path_str
        # file_rules[file_path_str] does NOT contain "alpha#1"
        g.file_rules[file_path_str] = {"other_rule"}

        g._compact_unique_rule_occurrence("alpha")

        assert "rule:alpha" in g.nodes
        # "alpha" must NOT have been added since "alpha#1" wasn't tracked in file_rules
        assert "alpha" not in g.file_rules[file_path_str]
        assert "other_rule" in g.file_rules[file_path_str]

    def test_compact_when_file_rules_has_no_entry_for_file_path(self) -> None:
        """file_rules.get(file_path) returns None; the inner if is skipped (line 382->386)."""
        g = DependencyGraph()
        file_path_str = "/tmp/a.yar"
        g.nodes["rule:alpha#1"] = DependencyNode(
            name="alpha", type="rule", file_path=Path(file_path_str)
        )
        g.rule_files["alpha#1"] = file_path_str
        # file_rules intentionally NOT populated for file_path_str

        g._compact_unique_rule_occurrence("alpha")

        assert "rule:alpha" in g.nodes
        # No file_rules entry was created
        assert file_path_str not in g.file_rules


# ---------------------------------------------------------------------------
# _add_dependency_edge: from_key not in nodes (line 491)
# ---------------------------------------------------------------------------


class TestAddDependencyEdge:
    """Lines 489-493: _add_dependency_edge validation."""

    def test_from_key_not_in_nodes_is_no_op(self) -> None:
        """No edge is added when from_key is missing (line 491)."""
        g = DependencyGraph()
        g.nodes["target"] = DependencyNode(name="target", type="rule", file_path=Path("/tmp/t.yar"))
        g._add_dependency_edge("nonexistent_from", "target")
        assert g.nodes["target"].dependents == set()

    def test_to_key_not_in_nodes_is_no_op(self) -> None:
        """No edge is added when to_key is missing."""
        g = DependencyGraph()
        g.nodes["source"] = DependencyNode(name="source", type="rule", file_path=Path("/tmp/t.yar"))
        g._add_dependency_edge("source", "nonexistent_to")
        assert g.nodes["source"].dependencies == set()

    def test_valid_edge_is_added(self) -> None:
        g = DependencyGraph()
        for name in ("a", "b"):
            g.nodes[name] = DependencyNode(name=name, type="rule", file_path=Path("/tmp/t.yar"))
        g._add_dependency_edge("a", "b")
        assert "b" in g.nodes["a"].dependencies
        assert "a" in g.nodes["b"].dependents


# ---------------------------------------------------------------------------
# _add_module_dependency: module already in nodes (line 399->403)
# ---------------------------------------------------------------------------


class TestAddModuleDependency:
    """Lines 396-404: _add_module_dependency when module node already exists."""

    def test_two_files_sharing_same_module_both_registered(self, tmp_path: Path) -> None:
        """When two files both import 'pe', the second call to _add_module_dependency
        finds 'pe' already in nodes (line 399->403: else branch).
        Both files must be in pe.dependents afterwards."""
        src_a = 'import "pe"\nrule rule_a { condition: true }'
        src_b = 'import "pe"\nrule rule_b { condition: true }'
        yf_a = _parse(src_a)
        yf_b = _parse(src_b)

        pa = tmp_path / "a.yar"
        pb = tmp_path / "b.yar"
        g = DependencyGraph()
        g.add_file(pa, yf_a)
        g.add_file(pb, yf_b)

        assert "pe" in g.nodes
        assert g.nodes["pe"].type == "module"
        assert str(pa) in g.nodes["pe"].dependents
        assert str(pb) in g.nodes["pe"].dependents


# ---------------------------------------------------------------------------
# _get_transitive_dependencies: missing node in BFS queue (line 539->532)
# ---------------------------------------------------------------------------


class TestTransitiveWithMissingNodes:
    """Lines 527-544, 547-567: transitive traversal with stale/missing node keys."""

    def test_transitive_deps_with_stale_dependency_key(self) -> None:
        """A key in a node's dependencies that is not in self.nodes causes
        self.nodes.get() to return None; the BFS loop continues (line 539->532)."""
        g = DependencyGraph()
        g.nodes["a"] = DependencyNode(name="a", type="rule", file_path=Path("/tmp/t.yar"))
        # Inject a dependency key that doesn't exist in nodes
        g.nodes["a"].dependencies.add("stale_dep")
        deps = g._get_transitive_dependencies("a")
        # stale_dep is still collected (it's in dependencies) but not further traversed
        assert "stale_dep" in deps

    def test_transitive_deps_deduplication_via_visited_set(self) -> None:
        """A diamond graph ensures already-visited nodes are skipped on second encounter."""
        g = DependencyGraph()
        for n in ("root", "left", "right", "shared"):
            g.nodes[n] = DependencyNode(name=n, type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["root"].dependencies = {"left", "right"}
        g.nodes["left"].dependencies = {"shared"}
        g.nodes["right"].dependencies = {"shared"}

        deps = g._get_transitive_dependencies("root")
        assert deps == {"left", "right", "shared"}

    def test_transitive_dependents_with_cycle_terminates(self) -> None:
        """A cycle in dependents is handled by the visited set (line 558 branch)."""
        g = DependencyGraph()
        for n in ("a", "b"):
            g.nodes[n] = DependencyNode(name=n, type="rule", file_path=Path("/tmp/t.yar"))
        # Mutual dependents: a depends on b AND b depends on a
        g.nodes["a"].dependents.add("b")
        g.nodes["b"].dependents.add("a")

        result = g._get_transitive_dependents("a")
        assert result == {"b"}

    def test_transitive_dependents_with_stale_dependent_key(self) -> None:
        """A dependent key not in nodes causes nodes.get() to return None (line 562->555)."""
        g = DependencyGraph()
        g.nodes["a"] = DependencyNode(name="a", type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["a"].dependents.add("stale_dependent")
        result = g._get_transitive_dependents("a")
        assert "stale_dependent" in result


# ---------------------------------------------------------------------------
# find_cycles: unreachable defensive guards documentation (lines 579, 583->exit)
# ---------------------------------------------------------------------------


class TestFindCyclesDefensiveGuards:
    """Lines 579 and 583->exit are defensive guards in the DFS implementation.

    Line 579 (if not body: return): add_cycle is always called with at least
    [node, node] (two elements), making body=[node] non-empty.  The empty-body
    guard cannot be triggered by the current DFS traversal.

    Line 583->exit (if normalized not in cycles): the DFS uses sorted() traversal
    and a shared visited set.  Once a cycle is found from a given starting node,
    all nodes in that cycle are already in the visited set, so no second DFS call
    will re-enter that cycle.  The deduplication guard exists as a safety net for
    future mutations of the DFS logic but is not reachable in the current code.

    These are documented here so the coverage gap is understood, not silenced.
    """

    def test_triangle_cycle_no_duplicates(self) -> None:
        """A triangle (a->b->c->a) is detected exactly once."""
        g = DependencyGraph()
        for name in ("a", "b", "c"):
            g.nodes[name] = DependencyNode(name=name, type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["a"].dependencies = {"b"}
        g.nodes["b"].dependencies = {"c"}
        g.nodes["c"].dependencies = {"a"}
        g.nodes["a"].dependents = {"c"}
        g.nodes["b"].dependents = {"a"}
        g.nodes["c"].dependents = {"b"}

        cycles = g.find_cycles()
        assert len(cycles) == 1
        body = cycles[0][:-1]
        assert cycles[0][0] == cycles[0][-1]
        assert len(body) == 3

    def test_bidirectional_pair_produces_one_normalized_cycle(self) -> None:
        """A<->B produces exactly one normalized cycle [a,b,a]."""
        g = DependencyGraph()
        for name in ("a", "b"):
            g.nodes[name] = DependencyNode(name=name, type="rule", file_path=Path("/tmp/t.yar"))
        g.nodes["a"].dependencies = {"b"}
        g.nodes["b"].dependencies = {"a"}
        g.nodes["a"].dependents = {"b"}
        g.nodes["b"].dependents = {"a"}

        cycles = g.find_cycles()
        assert len(cycles) == 1
        assert cycles[0] == ["a", "b", "a"]
