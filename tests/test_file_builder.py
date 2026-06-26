"""Tests for YaraFileBuilder fluent API.

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import PlainString
from yaraast.builder.file_builder import YaraFileBuilder
from yaraast.builder.fluent_file_builder import yara_file
from yaraast.builder.rule_builder import RuleBuilder
from yaraast.errors import ValidationError


class TestYaraFileBuilderInitialization:
    """Test file builder initialization."""

    def test_builder_initialization(self) -> None:
        """Builder should initialize with empty lists."""
        builder = YaraFileBuilder()

        yara_file = builder.build()

        assert isinstance(yara_file, YaraFile)
        assert yara_file.imports == []
        assert yara_file.includes == []
        assert yara_file.rules == []


class TestYaraFileBuilderImports:
    """Test import functionality."""

    def test_add_single_import(self) -> None:
        """With_import should add single import statement."""
        builder = YaraFileBuilder()

        builder.with_import("pe")
        yara_file = builder.build()

        assert len(yara_file.imports) == 1
        assert isinstance(yara_file.imports[0], Import)
        assert yara_file.imports[0].module == "pe"

    def test_add_multiple_imports_sequentially(self) -> None:
        """Chaining with_import should add multiple imports."""
        builder = YaraFileBuilder()

        builder.with_import("pe").with_import("elf").with_import("math")
        yara_file = builder.build()

        assert len(yara_file.imports) == 3
        assert yara_file.imports[0].module == "pe"
        assert yara_file.imports[1].module == "elf"
        assert yara_file.imports[2].module == "math"

    def test_add_multiple_imports_at_once(self) -> None:
        """With_imports should add multiple imports in one call."""
        builder = YaraFileBuilder()

        builder.with_imports("pe", "elf", "math", "hash")
        yara_file = builder.build()

        assert len(yara_file.imports) == 4
        module_names = [imp.module for imp in yara_file.imports]
        assert "pe" in module_names
        assert "elf" in module_names
        assert "math" in module_names
        assert "hash" in module_names

    def test_combine_import_methods(self) -> None:
        """Combining with_import and with_imports should work."""
        builder = YaraFileBuilder()

        builder.with_import("pe").with_imports("elf", "math").with_import("hash")
        yara_file = builder.build()

        assert len(yara_file.imports) == 4

    @pytest.mark.parametrize("empty_import", ["", "   ", "\t"])
    def test_reject_empty_imports_without_partial_update(self, empty_import: str) -> None:
        """Empty import modules should be rejected before code generation."""
        builder = YaraFileBuilder().with_import("pe")

        with pytest.raises(ValidationError, match="Import module must not be empty"):
            builder.with_import(empty_import)

        with pytest.raises(ValidationError, match="Import module must not be empty"):
            builder.with_imports("math", empty_import)

        assert [imp.module for imp in builder.build().imports] == ["pe"]

        empty_builder = YaraFileBuilder()
        with pytest.raises(ValidationError, match="Import module must not be empty"):
            empty_builder.with_imports("pe", empty_import)
        assert empty_builder.build().imports == []


class TestYaraFileBuilderIncludes:
    """Test include functionality."""

    def test_add_single_include(self) -> None:
        """With_include should add single include statement."""
        builder = YaraFileBuilder()

        builder.with_include("common.yar")
        yara_file = builder.build()

        assert len(yara_file.includes) == 1
        assert isinstance(yara_file.includes[0], Include)
        assert yara_file.includes[0].path == "common.yar"

    def test_add_multiple_includes_sequentially(self) -> None:
        """Chaining with_include should add multiple includes."""
        builder = YaraFileBuilder()

        builder.with_include("common.yar").with_include("utils.yar").with_include("crypto.yar")
        yara_file = builder.build()

        assert len(yara_file.includes) == 3
        assert yara_file.includes[0].path == "common.yar"
        assert yara_file.includes[1].path == "utils.yar"
        assert yara_file.includes[2].path == "crypto.yar"

    def test_add_multiple_includes_at_once(self) -> None:
        """With_includes should add multiple includes in one call."""
        builder = YaraFileBuilder()

        builder.with_includes("common.yar", "utils.yar", "crypto.yar")
        yara_file = builder.build()

        assert len(yara_file.includes) == 3
        paths = [inc.path for inc in yara_file.includes]
        assert "common.yar" in paths
        assert "utils.yar" in paths
        assert "crypto.yar" in paths

    def test_combine_include_methods(self) -> None:
        """Combining with_include and with_includes should work."""
        builder = YaraFileBuilder()

        builder.with_include("a.yar").with_includes("b.yar", "c.yar").with_include("d.yar")
        yara_file = builder.build()

        assert len(yara_file.includes) == 4

    @pytest.mark.parametrize("empty_include", ["", "   ", "\t"])
    def test_reject_empty_includes_without_partial_update(self, empty_include: str) -> None:
        """Empty include paths should be rejected before code generation."""
        builder = YaraFileBuilder().with_include("common.yar")

        with pytest.raises(ValidationError, match="Include path must not be empty"):
            builder.with_include(empty_include)

        with pytest.raises(ValidationError, match="Include path must not be empty"):
            builder.with_includes("utils.yar", empty_include)

        assert [inc.path for inc in builder.build().includes] == ["common.yar"]

        empty_builder = YaraFileBuilder()
        with pytest.raises(ValidationError, match="Include path must not be empty"):
            empty_builder.with_includes("common.yar", empty_include)
        assert empty_builder.build().includes == []


class TestYaraFileBuilderRules:
    """Test rule functionality."""

    def test_add_single_rule_object(self) -> None:
        """With_rule should add Rule object."""
        builder = YaraFileBuilder()

        rule = Rule(
            name="TestRule",
            strings=[PlainString(identifier="$s", value=b"test")],
            condition=Identifier(name="$s"),
        )

        builder.with_rule(rule)
        yara_file = builder.build()

        assert len(yara_file.rules) == 1
        assert yara_file.rules[0].name == "TestRule"
        assert len(yara_file.rules[0].strings) == 1

    def test_add_single_rule_from_builder(self) -> None:
        """With_rule should accept RuleBuilder instance."""
        file_builder = YaraFileBuilder()

        rule_builder = RuleBuilder().with_name("TestRule").with_string("$s", "test")

        file_builder.with_rule(rule_builder)
        yara_file = file_builder.build()

        assert len(yara_file.rules) == 1
        assert yara_file.rules[0].name == "TestRule"

    def test_add_multiple_rules_sequentially(self) -> None:
        """Chaining with_rule should add multiple rules."""
        builder = YaraFileBuilder()

        rule1 = Rule(
            name="Rule1",
            strings=[PlainString(identifier="$s1", value=b"test1")],
            condition=Identifier(name="$s1"),
        )
        rule2 = Rule(
            name="Rule2",
            strings=[PlainString(identifier="$s2", value=b"test2")],
            condition=Identifier(name="$s2"),
        )

        builder.with_rule(rule1).with_rule(rule2)
        yara_file = builder.build()

        assert len(yara_file.rules) == 2
        assert yara_file.rules[0].name == "Rule1"
        assert yara_file.rules[1].name == "Rule2"

    def test_add_multiple_rules_at_once(self) -> None:
        """With_rules should add multiple rules in one call."""
        builder = YaraFileBuilder()

        rule1 = Rule(
            name="Rule1",
            strings=[PlainString(identifier="$s1", value=b"test1")],
            condition=Identifier(name="$s1"),
        )
        rule2 = Rule(
            name="Rule2",
            strings=[PlainString(identifier="$s2", value=b"test2")],
            condition=Identifier(name="$s2"),
        )

        builder.with_rules(rule1, rule2)
        yara_file = builder.build()

        assert len(yara_file.rules) == 2

    def test_reject_duplicate_rule_names_without_partial_update(self) -> None:
        """Duplicate rule names should be rejected before code generation."""
        builder = YaraFileBuilder().with_rule(Rule(name="DuplicateRule"))

        with pytest.raises(ValidationError, match="Duplicate rule identifier"):
            builder.with_rule(Rule(name="DuplicateRule"))

        with pytest.raises(ValidationError, match="Duplicate rule identifier"):
            builder.with_rules(Rule(name="NewRule"), Rule(name="DuplicateRule"))

        assert [rule.name for rule in builder.build().rules] == ["DuplicateRule"]

        empty_builder = YaraFileBuilder()
        with pytest.raises(ValidationError, match="Duplicate rule identifier"):
            empty_builder.with_rules(Rule(name="BatchRule"), Rule(name="BatchRule"))
        assert empty_builder.build().rules == []

    def test_reject_invalid_rule_names_without_partial_update(self) -> None:
        """Invalid direct rule names should be rejected before code generation."""
        builder = YaraFileBuilder().with_rule(Rule(name="ValidRule"))

        with pytest.raises(ValidationError, match="Invalid rule identifier"):
            builder.with_rule(Rule(name="bad-name"))

        with pytest.raises(ValidationError, match="Invalid rule identifier"):
            builder.with_rules(Rule(name="NewRule"), Rule(name="bad-name"))

        assert [rule.name for rule in builder.build().rules] == ["ValidRule"]

        empty_builder = YaraFileBuilder()
        with pytest.raises(ValidationError, match="Invalid rule identifier"):
            empty_builder.with_rules(Rule(name="BatchRule"), Rule(name="bad-name"))
        assert empty_builder.build().rules == []

    def test_reject_invalid_rule_inputs_without_partial_update(self) -> None:
        """Non-rule inputs should be rejected with a stable API error."""
        builder = YaraFileBuilder().with_rule(Rule(name="StableRule"))

        with pytest.raises(TypeError, match="Rule input must be a Rule or RuleBuilder"):
            builder.with_rule(cast(Any, object()))

        with pytest.raises(TypeError, match="Rule input must be a Rule or RuleBuilder"):
            builder.with_rules(Rule(name="NewRule"), cast(Any, object()))

        assert [rule.name for rule in builder.build().rules] == ["StableRule"]

        empty_builder = YaraFileBuilder()
        with pytest.raises(TypeError, match="Rule input must be a Rule or RuleBuilder"):
            empty_builder.with_rules(Rule(name="BatchRule"), cast(Any, object()))
        assert empty_builder.build().rules == []

    def test_reject_invalid_rule_structure_without_partial_update(self) -> None:
        """Structurally invalid rules should not enter builder state."""
        builder = YaraFileBuilder().with_rule(
            Rule(name="StableRule", condition=BooleanLiteral(True))
        )
        bad_rule = Rule(name="BadRule", condition=cast(Any, object()))

        with pytest.raises(TypeError, match=r"Rule\.condition must be an AST node"):
            builder.with_rule(bad_rule)

        with pytest.raises(TypeError, match=r"Rule\.condition must be an AST node"):
            builder.with_rules(Rule(name="NewRule"), bad_rule)

        assert [rule.name for rule in builder.build().rules] == ["StableRule"]

        empty_builder = YaraFileBuilder()
        with pytest.raises(TypeError, match=r"Rule\.condition must be an AST node"):
            empty_builder.with_rules(
                Rule(name="BatchRule", condition=BooleanLiteral(True)),
                bad_rule,
            )
        assert empty_builder.build().rules == []

    def test_direct_rule_inputs_are_copied_when_added(self) -> None:
        """Mutating source rules after insertion should not alter builder state."""
        rule = Rule(name="StableRule")
        builder = YaraFileBuilder().with_rule(rule)

        rule.name = "bad-name"

        assert [built_rule.name for built_rule in builder.build().rules] == ["StableRule"]

        first = Rule(name="BatchOne")
        second = Rule(name="BatchTwo")
        batch_builder = YaraFileBuilder().with_rules(first, second)

        first.name = "bad-name"
        second.name = "bad-name"

        assert [built_rule.name for built_rule in batch_builder.build().rules] == [
            "BatchOne",
            "BatchTwo",
        ]

    def test_add_mixed_rule_types(self) -> None:
        """With_rules should accept both Rule and RuleBuilder."""
        builder = YaraFileBuilder()

        rule_obj = Rule(
            name="DirectRule",
            strings=[PlainString(identifier="$s", value=b"test")],
            condition=Identifier(name="$s"),
        )
        rule_builder = RuleBuilder().with_name("BuilderRule").with_string("$s", "test")

        builder.with_rules(rule_obj, rule_builder)
        yara_file = builder.build()

        assert len(yara_file.rules) == 2
        assert yara_file.rules[0].name == "DirectRule"
        assert yara_file.rules[1].name == "BuilderRule"

    def test_add_rule_with_builder_function(self) -> None:
        """With_rule_builder should use builder function."""
        builder = YaraFileBuilder()

        def build_rule(rb: RuleBuilder) -> None:
            rb.with_name("FunctionRule").with_string("$s", "test").with_condition(
                Identifier(name="$s")
            )

        builder.with_rule_builder(build_rule)
        yara_file = builder.build()

        assert len(yara_file.rules) == 1
        assert yara_file.rules[0].name == "FunctionRule"

    def test_rule_builder_callback_must_be_callable(self) -> None:
        """With_rule_builder should reject invalid callbacks before calling them."""
        with pytest.raises(TypeError, match="Rule builder callback must be callable"):
            YaraFileBuilder().with_rule_builder(cast(Any, 123))

    def test_add_multiple_rules_with_builder_function(self) -> None:
        """Multiple with_rule_builder calls should work."""
        builder = YaraFileBuilder()

        def build_rule1(rb: RuleBuilder) -> None:
            rb.with_name("Rule1").with_string("$s1", "test1")

        def build_rule2(rb: RuleBuilder) -> None:
            rb.with_name("Rule2").with_string("$s2", "test2")

        builder.with_rule_builder(build_rule1).with_rule_builder(build_rule2)
        yara_file = builder.build()

        assert len(yara_file.rules) == 2


class TestYaraFileBuilderCompleteFiles:
    """Test building complete YARA files."""

    def test_build_file_with_all_components(self) -> None:
        """Build file with imports, includes, and rules."""
        builder = YaraFileBuilder()

        rule = Rule(
            name="DetectionRule",
            strings=[PlainString(identifier="$malware", value=b"malicious")],
            condition=Identifier(name="$malware"),
        )

        yara_file = (
            builder.with_imports("pe", "elf")
            .with_includes("common.yar", "utils.yar")
            .with_rule(rule)
            .build()
        )

        assert len(yara_file.imports) == 2
        assert len(yara_file.includes) == 2
        assert len(yara_file.rules) == 1
        assert yara_file.imports[0].module == "pe"
        assert yara_file.includes[0].path == "common.yar"
        assert yara_file.rules[0].name == "DetectionRule"

    def test_build_file_with_only_rules(self) -> None:
        """Build file with only rules (common case)."""
        builder = YaraFileBuilder()

        rule1 = Rule(
            name="Rule1",
            strings=[PlainString(identifier="$s1", value=b"test1")],
            condition=Identifier(name="$s1"),
        )
        rule2 = Rule(
            name="Rule2",
            strings=[PlainString(identifier="$s2", value=b"test2")],
            condition=Identifier(name="$s2"),
        )

        yara_file = builder.with_rules(rule1, rule2).build()

        assert yara_file.imports == []
        assert yara_file.includes == []
        assert len(yara_file.rules) == 2

    def test_build_file_with_only_imports(self) -> None:
        """Build file with only imports."""
        builder = YaraFileBuilder()

        yara_file = builder.with_imports("pe", "elf", "math").build()

        assert len(yara_file.imports) == 3
        assert yara_file.includes == []
        assert yara_file.rules == []

    def test_build_empty_file(self) -> None:
        """Build completely empty file."""
        builder = YaraFileBuilder()

        yara_file = builder.build()

        assert isinstance(yara_file, YaraFile)
        assert yara_file.imports == []
        assert yara_file.includes == []
        assert yara_file.rules == []


class TestYaraFileBuilderFluentAPI:
    """Test fluent API chain behavior."""

    def test_complete_fluent_chain(self) -> None:
        """Complete fluent API chain should work."""
        rule = Rule(
            name="TestRule",
            strings=[PlainString(identifier="$test", value=b"malware")],
            condition=Identifier(name="$test"),
        )

        yara_file = (
            YaraFileBuilder()
            .with_import("pe")
            .with_imports("elf", "math")
            .with_include("common.yar")
            .with_includes("utils.yar", "crypto.yar")
            .with_rule(rule)
            .build()
        )

        assert len(yara_file.imports) == 3
        assert len(yara_file.includes) == 3
        assert len(yara_file.rules) == 1

    def test_build_multiple_times_returns_different_objects(self) -> None:
        """Building multiple times should create different YaraFile objects."""
        builder = YaraFileBuilder().with_import("pe")

        file1 = builder.build()
        file2 = builder.build()

        assert file1 is not file2
        assert file1.imports[0].module == file2.imports[0].module

    def test_builder_reuse_after_build(self) -> None:
        """Builder should allow modifications after build."""
        builder = YaraFileBuilder().with_import("pe")

        file1 = builder.build()
        assert len(file1.imports) == 1

        builder.with_import("elf")
        file2 = builder.build()

        assert len(file1.imports) == 1
        assert len(file2.imports) == 2
        assert file2.imports[0].module == "pe"
        assert file2.imports[1].module == "elf"

    def test_build_returns_snapshot_of_rule_list(self) -> None:
        builder = YaraFileBuilder().with_rule(Rule(name="r1"))

        file1 = builder.build()
        file1.rules.append(Rule(name="external"))
        builder.with_rule(Rule(name="r2"))
        file2 = builder.build()

        assert [rule.name for rule in file1.rules] == ["r1", "external"]
        assert [rule.name for rule in file2.rules] == ["r1", "r2"]

    def test_fluent_file_build_returns_snapshots(self) -> None:
        builder = yara_file().import_module("pe").with_rule(Rule(name="r1"))

        file1 = builder.build()
        builder.import_module("elf").with_rule(Rule(name="r2"))
        file2 = builder.build()

        assert [imp.module for imp in file1.imports] == ["pe"]
        assert [rule.name for rule in file1.rules] == ["r1"]
        assert [imp.module for imp in file2.imports] == ["pe", "elf"]
        assert [rule.name for rule in file2.rules] == ["r1", "r2"]


class TestYaraFileBuilderRealWorldScenarios:
    """Test realistic YARA file construction scenarios."""

    def test_malware_detection_ruleset(self) -> None:
        """Build typical malware detection ruleset."""
        pe_header_rule = Rule(
            name="PE_Header_Check",
            strings=[PlainString(identifier="$mz", value=b"MZ")],
            condition=Identifier(name="$mz"),
        )

        suspicious_strings_rule = Rule(
            name="Suspicious_Strings",
            strings=[
                PlainString(identifier="$s1", value="cmd.exe"),
                PlainString(identifier="$s2", value="powershell"),
            ],
            condition=Identifier(name="$s1"),
        )

        yara_file = (
            YaraFileBuilder()
            .with_import("pe")
            .with_include("common_malware.yar")
            .with_rules(pe_header_rule, suspicious_strings_rule)
            .build()
        )

        assert len(yara_file.imports) == 1
        assert len(yara_file.includes) == 1
        assert len(yara_file.rules) == 2
        assert yara_file.rules[0].name == "PE_Header_Check"
        assert yara_file.rules[1].name == "Suspicious_Strings"

    def test_library_file_with_utility_rules(self) -> None:
        """Build library file with reusable utility rules."""
        is_pe = Rule(
            name="is_pe",
            strings=[],
            condition=Identifier(name="true"),  # Simplified
        )

        is_elf = Rule(
            name="is_elf",
            strings=[],
            condition=Identifier(name="true"),  # Simplified
        )

        yara_file = (
            YaraFileBuilder()
            .with_imports("pe", "elf", "math")
            .with_rule(is_pe)
            .with_rule(is_elf)
            .build()
        )

        assert len(yara_file.imports) == 3
        assert len(yara_file.rules) == 2

    def test_complex_file_with_builder_functions(self) -> None:
        """Build file using builder functions for complex rules."""
        builder = YaraFileBuilder().with_imports("pe", "hash")

        def build_entropy_rule(rb: RuleBuilder) -> None:
            rb.with_name("High_Entropy").with_string("$entropy", "test")

        def build_packed_rule(rb: RuleBuilder) -> None:
            rb.with_name("Packed_Binary").with_string("$upx", "UPX")

        yara_file = (
            builder.with_rule_builder(build_entropy_rule)
            .with_rule_builder(build_packed_rule)
            .build()
        )

        assert len(yara_file.rules) == 2
        assert yara_file.rules[0].name == "High_Entropy"
        assert yara_file.rules[1].name == "Packed_Binary"

    def test_incremental_file_construction(self) -> None:
        """Build file incrementally (common in programmatic generation)."""
        builder = YaraFileBuilder()

        # Add base imports
        builder.with_import("pe")

        # Conditionally add more imports
        needs_crypto = True
        if needs_crypto:
            builder.with_import("hash")

        # Add rules
        rule1 = Rule(
            name="Rule1",
            strings=[PlainString(identifier="$s", value=b"test")],
            condition=Identifier(name="$s"),
        )
        builder.with_rule(rule1)

        # Add includes
        builder.with_include("utils.yar")

        yara_file = builder.build()

        assert len(yara_file.imports) == 2
        assert len(yara_file.includes) == 1
        assert len(yara_file.rules) == 1
