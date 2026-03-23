"""Tests for RuleBuilder fluent API.

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.modifiers import RuleModifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import HexByte, HexString, HexWildcard, PlainString, RegexString
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.builder.rule_builder import RuleBuilder


class TestRuleBuilderInitialization:
    """Test rule builder initialization."""

    def test_builder_initialization_without_name(self) -> None:
        """Builder should initialize without name."""
        builder = RuleBuilder()

        assert builder._name is None
        assert builder._modifiers == []
        assert builder._tags == []
        assert builder._meta == {}
        assert builder._strings == []
        assert builder._condition is None

    def test_builder_initialization_with_name(self) -> None:
        """Builder should initialize with provided name."""
        builder = RuleBuilder(name="TestRule")

        assert builder._name == "TestRule"

    def test_build_minimal_rule(self) -> None:
        """Build should create minimal valid rule."""
        builder = RuleBuilder(name="MinimalRule")

        rule = builder.build()

        assert isinstance(rule, Rule)
        assert rule.name == "MinimalRule"
        assert rule.strings == []


class TestRuleBuilderBasicProperties:
    """Test basic rule properties."""

    def test_with_name_sets_rule_name(self) -> None:
        """With_name should set rule name."""
        builder = RuleBuilder()

        builder.with_name("TestRule")
        rule = builder.build()

        assert rule.name == "TestRule"

    def test_with_name_fluent_api(self) -> None:
        """With_name should return self for chaining."""
        builder = RuleBuilder()

        result = builder.with_name("TestRule")

        assert result is builder

    def test_private_modifier(self) -> None:
        """Private method should add private modifier."""
        builder = RuleBuilder(name="PrivateRule")

        builder.private()
        rule = builder.build()

        assert len(rule.modifiers) == 1
        assert isinstance(rule.modifiers[0], RuleModifier)
        assert rule.modifiers[0].name == "private"

    def test_global_modifier(self) -> None:
        """Global_ method should add global modifier."""
        builder = RuleBuilder(name="GlobalRule")

        builder.global_()
        rule = builder.build()

        assert len(rule.modifiers) == 1
        assert rule.modifiers[0].name == "global"

    def test_multiple_modifiers(self) -> None:
        """Builder should support multiple modifiers."""
        builder = RuleBuilder(name="ModifiedRule")

        builder.private().global_()
        rule = builder.build()

        assert len(rule.modifiers) == 2
        modifier_names = [m.name for m in rule.modifiers]
        assert "private" in modifier_names
        assert "global" in modifier_names

    def test_private_modifier_idempotent(self) -> None:
        """Calling private multiple times should only add once."""
        builder = RuleBuilder(name="TestRule")

        builder.private().private()
        rule = builder.build()

        assert len(rule.modifiers) == 1

    def test_global_modifier_idempotent(self) -> None:
        """Calling global_ multiple times should only add once."""
        builder = RuleBuilder(name="TestRule")

        builder.global_().global_()
        rule = builder.build()

        assert len(rule.modifiers) == 1


class TestRuleBuilderTags:
    """Test tag functionality."""

    def test_with_tag_adds_single_tag(self) -> None:
        """With_tag should add single tag."""
        builder = RuleBuilder(name="TaggedRule")

        builder.with_tag("malware")
        rule = builder.build()

        assert len(rule.tags) == 1
        assert isinstance(rule.tags[0], Tag)
        assert rule.tags[0].name == "malware"

    def test_with_tags_adds_multiple_tags(self) -> None:
        """With_tags should add multiple tags at once."""
        builder = RuleBuilder(name="TaggedRule")

        builder.with_tags("malware", "trojan", "ransomware")
        rule = builder.build()

        assert len(rule.tags) == 3
        tag_names = [t.name for t in rule.tags]
        assert "malware" in tag_names
        assert "trojan" in tag_names
        assert "ransomware" in tag_names

    def test_combine_tag_methods(self) -> None:
        """Combining with_tag and with_tags should work."""
        builder = RuleBuilder(name="TaggedRule")

        builder.with_tag("malware").with_tags("trojan", "apt").with_tag("targeted")
        rule = builder.build()

        assert len(rule.tags) == 4

    def test_tags_allow_duplicates(self) -> None:
        """Tags should allow duplicates (YARA behavior)."""
        builder = RuleBuilder(name="TestRule")

        builder.with_tag("test").with_tag("test")
        rule = builder.build()

        assert len(rule.tags) == 2


class TestRuleBuilderMetadata:
    """Test metadata functionality."""

    def test_with_meta_adds_metadata(self) -> None:
        """With_meta should add metadata field."""
        builder = RuleBuilder(name="MetaRule")

        builder.with_meta("author", "John Doe")
        rule = builder.build()

        assert len(rule.meta) == 1
        assert isinstance(rule.meta, list)
        assert rule.get_meta_value("author") == "John Doe"

    def test_add_meta_alias(self) -> None:
        """Add_meta should work as alias for with_meta."""
        builder = RuleBuilder(name="MetaRule")

        builder.add_meta("version", 1)
        rule = builder.build()

        assert len(rule.meta) == 1
        assert rule.get_meta_value("version") == 1

    def test_with_author_convenience_method(self) -> None:
        """With_author should add author metadata."""
        builder = RuleBuilder(name="AuthoredRule")

        builder.with_author("Jane Smith")
        rule = builder.build()

        assert len(rule.meta) == 1
        assert rule.get_meta_value("author") == "Jane Smith"

    def test_with_description_convenience_method(self) -> None:
        """With_description should add description metadata."""
        builder = RuleBuilder(name="DescribedRule")

        builder.with_description("Detects malware")
        rule = builder.build()

        assert len(rule.meta) == 1
        assert rule.get_meta_value("description") == "Detects malware"

    def test_with_version_convenience_method(self) -> None:
        """With_version should add version metadata."""
        builder = RuleBuilder(name="VersionedRule")

        builder.with_version(2)
        rule = builder.build()

        assert len(rule.meta) == 1
        assert rule.get_meta_value("version") == 2

    def test_multiple_metadata_fields(self) -> None:
        """Builder should support multiple metadata fields."""
        builder = RuleBuilder(name="MetaRule")

        builder.with_author("Alice").with_description("Test rule").with_version(1).with_meta(
            "date", "2025-01-30"
        )
        rule = builder.build()

        assert len(rule.meta) == 4
        assert rule.get_meta_value("author") is not None
        assert rule.get_meta_value("description") is not None
        assert rule.get_meta_value("version") is not None
        assert rule.get_meta_value("date") is not None

    def test_metadata_types(self) -> None:
        """Metadata should support string, int, and bool values."""
        builder = RuleBuilder(name="TypedMetaRule")

        builder.with_meta("name", "test").with_meta("count", 42).with_meta("active", True)
        rule = builder.build()

        assert len(rule.meta) == 3
        assert rule.get_meta_value("name") == "test"
        assert rule.get_meta_value("count") == 42
        assert rule.get_meta_value("active") is True


class TestRuleBuilderPlainStrings:
    """Test text string functionality."""

    def test_with_string_basic(self) -> None:
        """With_text_string should add text string."""
        builder = RuleBuilder(name="StringRule")

        builder.with_string("$s", "malware")
        rule = builder.build()

        assert len(rule.strings) == 1
        assert isinstance(rule.strings[0], PlainString)
        assert rule.strings[0].identifier == "$s"
        assert rule.strings[0].value == "malware"

    def test_with_string_with_modifiers(self) -> None:
        """With_text_string should accept modifiers."""
        builder = RuleBuilder(name="ModifiedStringRule")

        builder.with_string("$s", "test", nocase=True, wide=True)
        rule = builder.build()

        string_def = rule.strings[0]
        assert len(string_def.modifiers) == 2
        modifier_names = [m.name for m in string_def.modifiers]
        assert "nocase" in modifier_names
        assert "wide" in modifier_names

    def test_multiple_text_strings(self) -> None:
        """Builder should support multiple text strings."""
        builder = RuleBuilder(name="MultiStringRule")

        builder.with_string("$s1", "test1").with_string("$s2", "test2").with_string("$s3", "test3")
        rule = builder.build()

        assert len(rule.strings) == 3
        assert rule.strings[0].identifier == "$s1"
        assert rule.strings[1].identifier == "$s2"
        assert rule.strings[2].identifier == "$s3"


class TestRuleBuilderBytesPlainStrings:
    """Test plain bytes string functionality."""

    def test_with_plain_string_basic(self) -> None:
        """With_plain_string should add plain string."""
        builder = RuleBuilder(name="PlainStringRule")

        builder.with_plain_string("$p", b"binary\x00data")
        rule = builder.build()

        assert len(rule.strings) == 1
        assert isinstance(rule.strings[0], PlainString)
        assert rule.strings[0].identifier == "$p"

    def test_with_plain_string_with_modifiers(self) -> None:
        """With_plain_string should accept modifiers."""
        builder = RuleBuilder(name="ModifiedPlainRule")

        builder.with_plain_string("$p", b"test", ascii=True, wide=True)
        rule = builder.build()

        string_def = rule.strings[0]
        assert len(string_def.modifiers) >= 1


class TestRuleBuilderRegexStrings:
    """Test regex string functionality."""

    def test_with_regex_string_basic(self) -> None:
        """With_regex_string should add regex string."""
        builder = RuleBuilder(name="RegexRule")

        builder.with_regex_string("$re", r"[a-zA-Z0-9]+")
        rule = builder.build()

        assert len(rule.strings) == 1
        assert isinstance(rule.strings[0], RegexString)
        assert rule.strings[0].identifier == "$re"
        assert rule.strings[0].regex == r"[a-zA-Z0-9]+"

    def test_with_regex_string_with_modifiers(self) -> None:
        """With_regex_string should accept modifiers."""
        builder = RuleBuilder(name="ModifiedRegexRule")

        builder.with_regex_string("$re", r"\w+", nocase=True)
        rule = builder.build()

        string_def = rule.strings[0]
        assert len(string_def.modifiers) == 1
        assert string_def.modifiers[0].name == "nocase"

    def test_multiple_regex_strings(self) -> None:
        """Builder should support multiple regex strings."""
        builder = RuleBuilder(name="MultiRegexRule")

        builder.with_regex_string("$re1", r"[0-9]+").with_regex_string(
            "$re2", r"[a-z]+"
        ).with_regex_string("$re3", r"[A-Z]+")
        rule = builder.build()

        assert len(rule.strings) == 3


class TestRuleBuilderHexStrings:
    """Test hex string functionality."""

    def test_with_hex_string_from_tokens(self) -> None:
        """With_hex_string should accept token list."""
        builder = RuleBuilder(name="HexRule")

        tokens = [HexByte(value=0x4D), HexByte(value=0x5A), HexWildcard()]

        builder.with_hex_string("$hex", tokens)
        rule = builder.build()

        assert len(rule.strings) == 1
        assert isinstance(rule.strings[0], HexString)
        assert rule.strings[0].identifier == "$hex"
        assert len(rule.strings[0].tokens) == 3

    def test_with_hex_string_from_builder(self) -> None:
        """With_hex_string should accept HexStringBuilder."""
        rule_builder = RuleBuilder(name="HexBuilderRule")

        hex_builder = HexStringBuilder().add(0x4D).add(0x5A).wildcard()

        rule_builder.with_hex_string("$hex", hex_builder)
        rule = rule_builder.build()

        assert len(rule.strings) == 1
        hex_string = rule.strings[0]
        assert isinstance(hex_string, HexString)
        assert len(hex_string.tokens) == 3

    def test_with_hex_string_builder_method(self) -> None:
        """With_hex_string_builder should use builder function."""
        builder = RuleBuilder(name="HexFunctionRule")

        def build_hex(hb: HexStringBuilder) -> None:
            hb.add(0xFF).add(0xAA).wildcard(2)

        builder.with_hex_string_builder("$hex", build_hex)
        rule = builder.build()

        assert len(rule.strings) == 1
        assert len(rule.strings[0].tokens) == 4


class TestRuleBuilderConditions:
    """Test condition functionality."""

    def test_with_condition_sets_condition(self) -> None:
        """With_condition should set rule condition."""
        builder = RuleBuilder(name="ConditionRule")

        condition = BooleanLiteral(value=True)
        builder.with_condition(condition)
        rule = builder.build()

        assert rule.condition is not None
        assert isinstance(rule.condition, BooleanLiteral)

    def test_with_simple_condition_helper(self) -> None:
        """With_simple_condition should create simple condition."""
        builder = RuleBuilder(name="SimpleConditionRule")

        builder.with_string("$s", "test")
        builder.with_simple_condition("$s")
        rule = builder.build()

        assert rule.condition is not None
        assert isinstance(rule.condition, Identifier)

    def test_with_any_string_condition(self) -> None:
        """With_any_string should create 'any of them' condition."""
        builder = RuleBuilder(name="AnyStringRule")

        builder.with_string("$s1", "test1").with_string("$s2", "test2")
        builder.with_any_string()
        rule = builder.build()

        assert rule.condition is not None

    def test_with_all_strings_condition(self) -> None:
        """With_all_strings should create 'all of them' condition."""
        builder = RuleBuilder(name="AllStringsRule")

        builder.with_string("$s1", "test1").with_string("$s2", "test2")
        builder.with_all_strings()
        rule = builder.build()

        assert rule.condition is not None


class TestRuleBuilderCompleteRules:
    """Test building complete rules."""

    def test_build_simple_detection_rule(self) -> None:
        """Build simple malware detection rule."""
        rule = (
            RuleBuilder()
            .with_name("SimpleMalware")
            .with_tag("malware")
            .with_author("Security Researcher")
            .with_description("Detects simple malware")
            .with_string("$s1", "malicious", nocase=True)
            .with_string("$s2", "payload")
            .with_any_string()
            .build()
        )

        assert rule.name == "SimpleMalware"
        assert len(rule.tags) == 1
        assert len(rule.meta) == 2
        assert len(rule.strings) == 2
        assert rule.condition is not None

    def test_build_pe_header_detection_rule(self) -> None:
        """Build PE header detection rule with hex strings."""
        rule = (
            RuleBuilder(name="PE_Detection")
            .with_tag("pe")
            .with_tag("windows")
            .with_hex_string_builder(
                "$mz_header",
                lambda hb: hb.add(0x4D).add(0x5A),
            )
            .with_hex_string_builder(
                "$pe_header",
                lambda hb: hb.add(0x50).add(0x45).add(0x00).add(0x00),
            )
            .with_any_string()
            .build()
        )

        assert rule.name == "PE_Detection"
        assert len(rule.tags) == 2
        assert len(rule.strings) == 2
        assert all(isinstance(s, HexString) for s in rule.strings)

    def test_build_private_global_rule(self) -> None:
        """Build rule with modifiers."""
        rule = (
            RuleBuilder(name="UtilityRule")
            .private()
            .global_()
            .with_description("Utility rule for other rules")
            .with_condition(BooleanLiteral(value=True))
            .build()
        )

        assert rule.name == "UtilityRule"
        assert len(rule.modifiers) == 2
        assert rule.condition is not None

    def test_build_complex_malware_rule(self) -> None:
        """Build complex malware detection rule."""
        rule = (
            RuleBuilder(name="ComplexTrojan")
            .with_tags("trojan", "apt", "targeted")
            .with_author("Threat Intel Team")
            .with_description("Detects advanced trojan")
            .with_version(2)
            .with_meta("date", "2025-01-30")
            .with_meta("severity", "critical")
            .with_string("$cmd", "cmd.exe", nocase=True)
            .with_string("$ps", "powershell", nocase=True)
            .with_regex_string("$url", r"https?://[a-zA-Z0-9.-]+\.[a-z]{2,}")
            .with_hex_string_builder(
                "$shellcode",
                lambda hb: hb.add(0x48)
                .nibble("8?")
                .wildcard(2)
                .jump_varying(2, 8)
                .add(0xFF)
                .add(0xD0),
            )
            .with_any_string()
            .build()
        )

        assert rule.name == "ComplexTrojan"
        assert len(rule.tags) == 3
        assert len(rule.meta) == 5
        assert len(rule.strings) == 4

        # Verify string types
        string_types = [type(s).__name__ for s in rule.strings]
        assert "PlainString" in string_types
        assert "RegexString" in string_types
        assert "HexString" in string_types


class TestRuleBuilderFluentAPI:
    """Test fluent API behavior."""

    def test_all_methods_return_self(self) -> None:
        """All builder methods should return self for chaining."""
        builder = RuleBuilder()

        result = (
            builder.with_name("Test")
            .private()
            .global_()
            .with_tag("test")
            .with_tags("tag1", "tag2")
            .with_meta("key", "value")
            .with_author("Author")
            .with_description("Description")
            .with_version(1)
            .with_string("$s", "test")
        )

        assert result is builder

    def test_build_multiple_times_creates_different_objects(self) -> None:
        """Build should create new Rule objects each time."""
        builder = RuleBuilder(name="TestRule").with_string("$s", "test")

        rule1 = builder.build()
        rule2 = builder.build()

        assert rule1 is not rule2
        assert rule1.name == rule2.name

    def test_builder_reuse_after_build(self) -> None:
        """Builder should allow modifications after build."""
        builder = RuleBuilder(name="TestRule")

        rule1 = builder.build()
        assert len(rule1.strings) == 0

        builder.with_string("$s", "test")
        rule2 = builder.build()

        assert len(rule2.strings) == 1

    def test_complete_fluent_chain(self) -> None:
        """Complete fluent chain should work seamlessly."""
        rule = (
            RuleBuilder()
            .with_name("FluentRule")
            .private()
            .with_tags("test", "fluent")
            .with_author("Builder Test")
            .with_string("$s1", "test")
            .with_regex_string("$re", r"\w+")
            .with_hex_string_builder("$hex", lambda hb: hb.add(0xFF))
            .with_any_string()
            .build()
        )

        assert isinstance(rule, Rule)
        assert rule.name == "FluentRule"


class TestRuleBuilderErrorCases:
    """Test error handling."""

    def test_build_without_name_raises_error(self) -> None:
        """Building without name should raise ValueError."""
        builder = RuleBuilder()

        with pytest.raises(ValueError, match="Rule name is required"):
            builder.build()

    def test_build_without_condition_raises_error(self) -> None:
        """Building without condition should raise ValueError."""
        builder = RuleBuilder(name="NoConditionRule")

        with pytest.raises(ValueError, match="Rule condition is required"):
            builder.require_condition().build()
