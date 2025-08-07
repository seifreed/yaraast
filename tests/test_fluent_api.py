"""Tests for the fluent API."""

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.builder import (
    all_of_them,
    any_of_them,
    clone_rule,
    hex_pattern,
    malware_rule,
    match,
    regex,
    rule,
    string,
    text,
    transform_rule,
    trojan_rule,
    yara_file,
)
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.codegen import CodeGenerator


class TestFluentStringBuilder:
    """Tests for fluent string builder."""

    def test_text_string_basic(self) -> None:
        """Test basic text string creation."""
        string_def = text("$test", "hello world").build()

        assert string_def.identifier == "$test"
        assert string_def.value == "hello world"
        assert len(string_def.modifiers) == 0

    def test_text_string_with_modifiers(self) -> None:
        """Test text string with modifiers."""
        string_def = text("$test", "malware").nocase().wide().fullword().build()

        assert string_def.identifier == "$test"
        assert string_def.value == "malware"
        assert len(string_def.modifiers) == 3

        modifier_names = [mod.name for mod in string_def.modifiers]
        assert "nocase" in modifier_names
        assert "wide" in modifier_names
        assert "fullword" in modifier_names

    def test_hex_string_basic(self) -> None:
        """Test basic hex string creation."""
        string_def = hex_pattern("$hex", "4D 5A ?? 00").build()

        assert string_def.identifier == "$hex"
        assert len(string_def.tokens) > 0

    def test_regex_string_basic(self) -> None:
        """Test basic regex string creation."""
        string_def = regex(
            "$email",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        ).build()

        assert string_def.identifier == "$email"
        assert "@" in string_def.regex

    def test_pattern_helpers(self) -> None:
        """Test pattern helper methods."""
        mz = string("$mz").mz_header().build()
        assert mz.identifier == "$mz"

        pe = string("$pe").pe_header().build()
        assert pe.identifier == "$pe"

        email = string("$email").email_pattern().build()
        assert email.identifier == "$email"


class TestFluentConditionBuilder:
    """Tests for fluent condition builder."""

    def test_string_match(self) -> None:
        """Test string matching condition."""
        cond = match("$test").build()
        assert cond is not None

    def test_logical_operators(self) -> None:
        """Test logical operators."""
        cond = match("$a").and_(match("$b")).or_(match("$c")).build()
        assert cond is not None

    def test_quantifiers(self) -> None:
        """Test quantifier conditions."""
        cond1 = any_of_them().build()
        assert cond1 is not None

        cond2 = all_of_them().build()
        assert cond2 is not None

        cond3 = FluentConditionBuilder().one_of("$a", "$b", "$c").build()
        assert cond3 is not None

    def test_file_properties(self) -> None:
        """Test file property conditions."""
        cond1 = FluentConditionBuilder().filesize_gt(1024).build()
        assert cond1 is not None

        cond2 = FluentConditionBuilder().small_file().build()
        assert cond2 is not None


class TestFluentRuleBuilder:
    """Tests for fluent rule builder."""

    def test_basic_rule(self) -> None:
        """Test basic rule creation."""
        rule_ast = (
            rule("test_rule")
            .tagged("test")
            .authored_by("Test Author")
            .text_string("$test", "hello")
            .matches_any()
            .build()
        )

        assert isinstance(rule_ast, Rule)
        assert rule_ast.name == "test_rule"
        assert len(rule_ast.tags) == 1
        assert rule_ast.tags[0].name == "test"
        assert "author" in rule_ast.meta
        assert rule_ast.meta["author"] == "Test Author"
        assert len(rule_ast.strings) == 1
        assert rule_ast.condition is not None

    def test_rule_with_multiple_strings(self) -> None:
        """Test rule with multiple strings."""
        rule_ast = (
            rule("multi_string_rule")
            .text_string("$a", "hello")
            .text_string("$b", "world")
            .hex_string("$c", "4D 5A")
            .matches_any()
            .build()
        )

        assert len(rule_ast.strings) == 3
        assert rule_ast.strings[0].identifier == "$a"
        assert rule_ast.strings[1].identifier == "$b"
        assert rule_ast.strings[2].identifier == "$c"

    def test_rule_with_fluent_strings(self) -> None:
        """Test rule with fluent string context."""
        rule_ast = (
            rule("fluent_strings")
            .string("$a")
            .text("malware")
            .nocase()
            .then()
            .string("$b")
            .hex("4D 5A")
            .then()
            .string("$c")
            .regex(r"\d+\.\d+\.\d+\.\d+")
            .then()
            .matches_any()
            .build()
        )

        assert len(rule_ast.strings) == 3
        assert rule_ast.strings[0].identifier == "$a"
        assert len(rule_ast.strings[0].modifiers) == 1
        assert rule_ast.strings[0].modifiers[0].name == "nocase"

    def test_malware_rule_template(self) -> None:
        """Test malware rule template."""
        rule_ast = malware_rule("test_malware").build()

        assert rule_ast.name == "test_malware"
        assert any(tag.name == "malware" for tag in rule_ast.tags)
        assert "author" in rule_ast.meta
        assert len(rule_ast.strings) > 0  # Should have MZ header
        assert rule_ast.condition is not None

    def test_trojan_rule_template(self) -> None:
        """Test trojan rule template."""
        rule_ast = trojan_rule("test_trojan").build()

        assert rule_ast.name == "test_trojan"
        assert any(tag.name == "trojan" for tag in rule_ast.tags)
        assert any(tag.name == "malware" for tag in rule_ast.tags)


class TestYaraFileBuilder:
    """Tests for YARA file builder."""

    def test_basic_file(self) -> None:
        """Test basic YARA file creation."""
        yara_ast = (
            yara_file()
            .import_module("pe")
            .import_module("math", "m")
            .include_file("common.yar")
            .build()
        )

        assert isinstance(yara_ast, YaraFile)
        assert len(yara_ast.imports) == 2
        assert yara_ast.imports[0].module == "pe"
        assert yara_ast.imports[1].module == "math"
        assert yara_ast.imports[1].alias == "m"
        assert len(yara_ast.includes) == 1
        assert yara_ast.includes[0].path == "common.yar"

    def test_file_with_rules(self) -> None:
        """Test YARA file with rules."""
        rule1 = rule("rule1").text_string("$a", "test").matches_any().build()
        rule2 = rule("rule2").hex_string("$b", "4D 5A").matches_any().build()

        yara_ast = yara_file().with_rule(rule1).with_rule(rule2).build()

        assert len(yara_ast.rules) == 2
        assert yara_ast.rules[0].name == "rule1"
        assert yara_ast.rules[1].name == "rule2"

    def test_chained_rule_building(self) -> None:
        """Test chained rule building in file."""
        yara_ast = (
            yara_file()
            .import_module("pe")
            .rule("first_rule")
            .text_string("$a", "hello")
            .matches_any()
            .then_rule("second_rule")
            .hex_string("$b", "4D 5A")
            .matches_any()
            .then_build_file()
        )

        assert isinstance(yara_ast, YaraFile)
        assert len(yara_ast.imports) == 1
        assert len(yara_ast.rules) == 2
        assert yara_ast.rules[0].name == "first_rule"
        assert yara_ast.rules[1].name == "second_rule"


class TestRuleTransformations:
    """Tests for rule transformations."""

    def test_clone_rule(self) -> None:
        """Test rule cloning."""
        original = rule("original").tagged("test").text_string("$a", "hello").matches_any().build()

        cloned = clone_rule(original)

        assert cloned.name == original.name
        assert cloned is not original  # Different object
        assert len(cloned.tags) == len(original.tags)
        assert len(cloned.strings) == len(original.strings)

    def test_transform_rule_rename(self) -> None:
        """Test rule transformation - renaming."""
        original = rule("original").text_string("$a", "hello").matches_any().build()

        transformed = transform_rule(original).rename("transformed").build()

        assert transformed.name == "transformed"
        assert original.name == "original"  # Original unchanged

    def test_transform_rule_tags(self) -> None:
        """Test rule transformation - tags."""
        original = rule("test").tagged("original").text_string("$a", "hello").matches_any().build()

        transformed = transform_rule(original).add_tag("new").remove_tag("original").build()

        tag_names = [tag.name for tag in transformed.tags]
        assert "new" in tag_names
        assert "original" not in tag_names

    def test_transform_rule_prefix(self) -> None:
        """Test rule transformation - prefix."""
        original = (
            rule("test").text_string("$a", "hello").text_string("$b", "world").matches_any().build()
        )

        transformed = transform_rule(original).add_prefix("win32_").prefix_strings("str_").build()

        assert transformed.name == "win32_test"
        string_ids = [s.identifier for s in transformed.strings]
        assert "$str_a" in string_ids
        assert "$str_b" in string_ids


class TestCodeGeneration:
    """Tests for code generation from fluent API."""

    def test_generate_simple_rule(self) -> None:
        """Test generating code from simple rule."""
        rule_ast = rule("simple_test").text_string("$test", "hello").matches_any().build()

        generator = CodeGenerator()
        code = generator.generate(rule_ast)

        assert "rule simple_test" in code
        assert '$test = "hello"' in code
        assert "condition:" in code

    def test_generate_complex_file(self) -> None:
        """Test generating code from complex YARA file."""
        yara_ast = (
            yara_file()
            .import_module("pe")
            .rule("complex_rule")
            .tagged("malware", "test")
            .authored_by("Test")
            .mz_header()
            .text_string("$str", "backdoor")
            .nocase()
            .with_condition_builder(
                lambda c: c.string_matches("$mz")
                .at(0)
                .and_(c.string_matches("$str"))
                .and_(c.filesize_gt(1024)),
            )
            .then_build_file()
        )

        generator = CodeGenerator()
        code = generator.generate(yara_ast)

        assert 'import "pe"' in code
        assert "rule complex_rule" in code
        assert "malware" in code
        assert "test" in code
        assert "author" in code
        assert "$mz" in code
        assert "$str" in code
        assert "nocase" in code
        assert "condition:" in code


if __name__ == "__main__":
    # Run a simple test
    print("Testing fluent API...")

    # Create a test rule
    rule_ast = (
        rule("fluent_test")
        .tagged("test", "fluent")
        .authored_by("Test Suite")
        .described_as("Fluent API test rule")
        .text_string("$hello", "hello world")
        .nocase()
        .hex_string("$mz", "4D 5A")
        .regex_string("$email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        .with_condition_builder(
            lambda c: c.string_matches("$hello")
            .and_(c.string_matches("$mz").at(0))
            .or_(c.string_matches("$email")),
        )
        .build()
    )

    print(f"✓ Created rule: {rule_ast.name}")
    print(f"✓ Tags: {[tag.name for tag in rule_ast.tags]}")
    print(f"✓ Strings: {len(rule_ast.strings)}")
    print(f"✓ Has condition: {rule_ast.condition is not None}")

    # Test transformation
    transformed = transform_rule(rule_ast).add_prefix("test_").add_tag("transformed").build()

    print(f"✓ Transformed rule: {transformed.name}")
    print(f"✓ New tags: {[tag.name for tag in transformed.tags]}")

    print("✅ Fluent API tests passed!")
