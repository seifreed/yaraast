"""Enhanced fluent rule builder with comprehensive chaining support."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Include, Rule
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.builder.rule_builder import RuleBuilder

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.expressions import Expression


class FluentRuleBuilder:
    """Enhanced fluent builder for YARA rules with comprehensive chaining."""

    # Constants
    MZ_HEADER = "MZ"
    YARA_AST_STR = "YARA AST"

    def __init__(self, name: str | None = None) -> None:
        self._rule_builder = RuleBuilder()
        if name:
            self._rule_builder.with_name(name)
        self._string_builders: list[FluentStringBuilder] = []

    # Rule metadata methods
    def named(self, name: str) -> Self:
        """Set the rule name."""
        self._rule_builder.with_name(name)
        return self

    def private(self) -> Self:
        """Mark rule as private."""
        self._rule_builder.private()
        return self

    def global_(self) -> Self:
        """Mark rule as global."""
        self._rule_builder.global_()
        return self

    def public(self) -> Self:
        """Mark rule as public (remove private modifier)."""
        # Remove private from modifiers
        self._rule_builder._modifiers = [m for m in self._rule_builder._modifiers if m != "private"]
        return self

    def tagged(self, *tags: str) -> Self:
        """Add tags to the rule."""
        self._rule_builder.with_tags(*tags)
        return self

    def with_tag(self, tag: str) -> Self:
        """Add a single tag."""
        self._rule_builder.with_tag(tag)
        return self

    def meta(self, key: str, value: str | int | bool) -> Self:
        """Add metadata."""
        self._rule_builder.with_meta(key, value)
        return self

    def with_meta(self, key: str, value: str | int | bool) -> Self:
        """Add metadata (alias for meta)."""
        return self.meta(key, value)

    def authored_by(self, author: str) -> Self:
        """Set author."""
        self._rule_builder.with_author(author)
        return self

    def described_as(self, description: str) -> Self:
        """Set description."""
        self._rule_builder.with_description(description)
        return self

    def versioned(self, version: int) -> Self:
        """Set version."""
        self._rule_builder.with_version(version)
        return self

    # String definition methods
    def with_string(
        self,
        identifier_or_builder: str | FluentStringBuilder,
        value: str | None = None,
    ) -> Self:
        """Add a string using FluentStringBuilder or simple string."""
        if isinstance(identifier_or_builder, str) and value is not None:
            # Simple string case
            builder = FluentStringBuilder.text_string(identifier_or_builder, value)
            self._string_builders.append(builder)
        elif isinstance(identifier_or_builder, FluentStringBuilder):
            # Builder case
            self._string_builders.append(identifier_or_builder)
        else:
            msg = "Either provide (identifier, value) or a FluentStringBuilder"
            raise ValueError(
                msg,
            )
        return self

    def string(self, identifier: str) -> FluentStringContext:
        """Start defining a string (returns context for chaining)."""
        return FluentStringContext(self, identifier)

    def text_string(self, identifier: str, content: str) -> Self:
        """Add a text string."""
        builder = FluentStringBuilder.text_string(identifier, content)
        return self.with_string(builder)

    def hex_string(self, identifier: str, pattern: str) -> Self:
        """Add a hex string."""
        builder = FluentStringBuilder.hex_string(identifier, pattern)
        return self.with_string(builder)

    def regex_string(self, identifier: str, pattern: str) -> Self:
        """Add a regex string."""
        builder = FluentStringBuilder.regex_string(identifier, pattern)
        return self.with_string(builder)

    # Common string patterns
    def with_mz_header(self, identifier: str = "$mz") -> Self:
        """Add MZ header string."""
        return self.with_string(FluentStringBuilder.string(identifier).mz_header())

    def pe_header(self, identifier: str = "$pe") -> Self:
        """Add PE header string."""
        return self.with_string(FluentStringBuilder.string(identifier).pe_header())

    def elf_header(self, identifier: str = "$elf") -> Self:
        """Add ELF header string."""
        return self.with_string(FluentStringBuilder.string(identifier).elf_header())

    def email_pattern(self, identifier: str = "$email") -> Self:
        """Add email regex pattern."""
        return self.with_string(FluentStringBuilder.string(identifier).email_pattern())

    def ip_pattern(self, identifier: str = "$ip") -> Self:
        """Add IP address regex pattern."""
        return self.with_string(
            FluentStringBuilder.string(identifier).ip_address_pattern(),
        )

    def url_pattern(self, identifier: str = "$url") -> Self:
        """Add URL regex pattern."""
        return self.with_string(FluentStringBuilder.string(identifier).url_pattern())

    # String modifier methods (apply to most recent string)
    def nocase(self) -> Self:
        """Add nocase modifier to the most recent string."""
        if self._string_builders:
            self._string_builders[-1].nocase()
        return self

    def ascii(self) -> Self:
        """Add ASCII modifier to the most recent string."""
        if self._string_builders:
            self._string_builders[-1].ascii()
        return self

    def wide(self) -> Self:
        """Add wide modifier to the most recent string."""
        if self._string_builders:
            self._string_builders[-1].wide()
        return self

    def fullword(self) -> Self:
        """Add fullword modifier to the most recent string."""
        if self._string_builders:
            self._string_builders[-1].fullword()
        return self

    def private_string(self) -> Self:
        """Add private modifier to the most recent string."""
        if self._string_builders:
            self._string_builders[-1].private()
        return self

    def xor(self, key: int | str | None = None) -> Self:
        """Add XOR modifier to the most recent string."""
        if self._string_builders:
            self._string_builders[-1].xor(key)
        return self

    def base64(self) -> Self:
        """Add base64 modifier to the most recent string."""
        if self._string_builders:
            self._string_builders[-1].base64()
        return self

    # Condition methods
    def condition(self, condition: str | Expression | FluentConditionBuilder) -> Self:
        """Set the rule condition."""
        if isinstance(condition, FluentConditionBuilder):
            self._rule_builder.with_condition(condition.build())
        else:
            self._rule_builder.with_condition(condition)
        return self

    def when(self, condition: str | Expression | FluentConditionBuilder) -> Self:
        """Alias for condition."""
        return self.condition(condition)

    def with_condition(
        self,
        condition: str | Expression | FluentConditionBuilder,
    ) -> Self:
        """Alias for condition."""
        return self.condition(condition)

    def matches_any(self) -> Self:
        """Condition: any of them."""
        return self.condition("any of them")

    def matches_all(self) -> Self:
        """Condition: all of them."""
        return self.condition("all of them")

    def matches_one_of(self, *strings: str) -> Self:
        """Condition: one of specified strings."""
        builder = FluentConditionBuilder().one_of(*strings)
        return self.condition(builder)

    def matches_any_of(self, *strings: str) -> Self:
        """Condition: any of specified strings."""
        builder = FluentConditionBuilder().any_of(*strings)
        return self.condition(builder)

    def matches_all_of(self, *strings: str) -> Self:
        """Condition: all of specified strings."""
        builder = FluentConditionBuilder().all_of(*strings)
        return self.condition(builder)

    def with_condition_builder(
        self,
        builder_func: Callable[[FluentConditionBuilder], FluentConditionBuilder],
    ) -> Self:
        """Set condition using a builder function."""
        condition_builder = FluentConditionBuilder()
        result = builder_func(condition_builder)
        return self.condition(result)

    # File property conditions
    def for_small_files(self) -> Self:
        """Add small file condition (< 1MB)."""
        condition_builder = FluentConditionBuilder().small_file()
        if self._rule_builder._condition:
            # Combine with existing condition
            existing = self._rule_builder._condition
            combined = FluentConditionBuilder(existing).and_(condition_builder)
            return self.condition(combined)
        return self.condition(condition_builder)

    def for_large_files(self) -> Self:
        """Add large file condition (> 10MB)."""
        condition_builder = FluentConditionBuilder().large_file()
        if self._rule_builder._condition:
            existing = self._rule_builder._condition
            combined = FluentConditionBuilder(existing).and_(condition_builder)
            return self.condition(combined)
        return self.condition(condition_builder)

    def for_pe_files(self) -> Self:
        """Add PE file conditions."""
        # Add MZ header if not already present
        if not any(s.identifier in ["$mz", self.MZ_HEADER] for s in self._string_builders):
            self.with_mz_header(self.MZ_HEADER)

        condition_builder = FluentConditionBuilder().string_matches(self.MZ_HEADER).at(0)
        if self._rule_builder._condition:
            existing = self._rule_builder._condition
            combined = FluentConditionBuilder(existing).and_(condition_builder)
            return self.condition(combined)
        return self.condition(condition_builder)

    def for_executables(self) -> Self:
        """Add executable file conditions."""
        return self.for_pe_files().for_large_files()

    # Build method
    def build(self) -> Rule:
        """Build the rule."""
        # Add all string builders to the rule builder
        for string_builder in self._string_builders:
            string_def = string_builder.build()
            self._rule_builder._strings.append(string_def)

        return self._rule_builder.build()


class FluentStringContext:
    """Context for fluent string building within a rule."""

    def __init__(self, rule_builder: FluentRuleBuilder, identifier: str) -> None:
        self.rule_builder = rule_builder
        self.string_builder = FluentStringBuilder(identifier)

    # String content methods
    def literal(self, content: str) -> FluentStringContext:
        """Set string content as literal."""
        self.string_builder.literal(content)
        return self

    def text(self, content: str) -> FluentStringContext:
        """Set string content as text."""
        self.string_builder.text(content)
        return self

    def hex(self, pattern: str) -> FluentStringContext:
        """Set string content as hex pattern."""
        self.string_builder.hex(pattern)
        return self

    def regex(self, pattern: str) -> FluentStringContext:
        """Set string content as regex."""
        self.string_builder.regex(pattern)
        return self

    # String modifiers
    def ascii(self) -> FluentStringContext:
        """Add ASCII modifier."""
        self.string_builder.ascii()
        return self

    def wide(self) -> FluentStringContext:
        """Add wide modifier."""
        self.string_builder.wide()
        return self

    def nocase(self) -> FluentStringContext:
        """Add nocase modifier."""
        self.string_builder.nocase()
        return self

    def fullword(self) -> FluentStringContext:
        """Add fullword modifier."""
        self.string_builder.fullword()
        return self

    def private(self) -> FluentStringContext:
        """Add private modifier."""
        self.string_builder.private()
        return self

    def xor(self, key: int | str | None = None) -> FluentStringContext:
        """Add XOR modifier."""
        self.string_builder.xor(key)
        return self

    def base64(self) -> FluentStringContext:
        """Add base64 modifier."""
        self.string_builder.base64()
        return self

    # Pattern helpers
    def with_mz_header_string(self) -> FluentStringContext:
        """Set as MZ header pattern."""
        self.string_builder.mz_header()
        return self

    def pe_header(self) -> FluentStringContext:
        """Set as PE header pattern."""
        self.string_builder.pe_header()
        return self

    def email_pattern(self) -> FluentStringContext:
        """Set as email regex pattern."""
        self.string_builder.email_pattern()
        return self

    # Return to rule builder
    def then(self) -> FluentRuleBuilder:
        """Return to rule builder after defining string."""
        self.rule_builder._string_builders.append(self.string_builder)
        return self.rule_builder

    def and_string(self, identifier: str) -> FluentStringContext:
        """Add this string and start another."""
        self.rule_builder._string_builders.append(self.string_builder)
        return FluentStringContext(self.rule_builder, identifier)


class FluentYaraFileBuilder:
    """Fluent builder for complete YARA files."""

    def __init__(self) -> None:
        self.imports: list[Import] = []
        self.includes: list[Include] = []
        self.rules: list[Rule] = []

    def import_module(self, module: str, alias: str | None = None) -> Self:
        """Add import statement."""
        if not any(imp.module == module for imp in self.imports):
            self.imports.append(Import(module=module, alias=alias))
        return self

    def include_file(self, path: str) -> Self:
        """Add include statement."""
        if not any(inc.path == path for inc in self.includes):
            self.includes.append(Include(path=path))
        return self

    def with_rule(self, rule: Rule) -> Self:
        """Add a rule."""
        self.rules.append(rule)
        return self

    def rule(self, name: str) -> FluentRuleBuilder:
        """Start building a rule."""
        return FluentRuleBuilderWithFile(self, name)

    def build(self) -> YaraFile:
        """Build the YARA file."""
        return YaraFile(imports=self.imports, includes=self.includes, rules=self.rules)


class FluentRuleBuilderWithFile(FluentRuleBuilder):
    """Rule builder that can return to file builder."""

    def __init__(self, file_builder: FluentYaraFileBuilder, name: str) -> None:
        super().__init__(name)
        self.file_builder = file_builder

    def then_rule(self, name: str) -> FluentRuleBuilderWithFile:
        """Add this rule and start another."""
        rule = self.build()
        self.file_builder.with_rule(rule)
        return FluentRuleBuilderWithFile(self.file_builder, name)

    def then_build_file(self) -> YaraFile:
        """Add this rule and build the file."""
        rule = self.build()
        self.file_builder.with_rule(rule)
        return self.file_builder.build()


# Convenience functions
def rule(name: str) -> FluentRuleBuilder:
    """Create a new fluent rule builder."""
    return FluentRuleBuilder(name)


def yara_file() -> FluentYaraFileBuilder:
    """Create a new fluent YARA file builder."""
    return FluentYaraFileBuilder()


# Factory functions for common rule types
def malware_rule(name: str) -> FluentRuleBuilder:
    """Create a malware detection rule template."""
    return (
        FluentRuleBuilder(name)
        .tagged("malware")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .mz_header()
        .for_pe_files()
    )


def trojan_rule(name: str) -> FluentRuleBuilder:
    """Create a trojan detection rule template."""
    return (
        FluentRuleBuilder(name)
        .tagged("trojan", "malware")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .mz_header()
        .for_pe_files()
    )


def packed_rule(name: str) -> FluentRuleBuilder:
    """Create a packed executable rule template."""
    return (
        FluentRuleBuilder(name)
        .tagged("packed")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .mz_header()
        .with_condition_builder(
            lambda c: c.string_matches("$mz").at(0).and_(c.high_entropy()),
        )
    )


def document_rule(name: str) -> FluentRuleBuilder:
    """Create a document-based rule template."""
    return FluentRuleBuilder(name).tagged("document").authored_by(FluentRuleBuilder.YARA_AST_STR)


def network_rule(name: str) -> FluentRuleBuilder:
    """Create a network-based detection rule."""
    return (
        FluentRuleBuilder(name)
        .tagged("network")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .ip_pattern()
        .url_pattern()
        .matches_any_of("$ip", "$url")
    )


# Example usage function
def example_rules() -> YaraFile:
    """Create example rules using the fluent API."""
    return (
        yara_file()
        .import_module("pe")
        .import_module("math")
        .rule("example_malware")
        .tagged("malware", "example")
        .authored_by("Fluent API Demo")
        .described_as("Example malware detection rule")
        .string("$mz")
        .hex("4D 5A")
        .then()
        .string("$pe")
        .hex("50 45 00 00")
        .then()
        .string("$suspicious")
        .text("backdoor")
        .nocase()
        .then()
        .when(
            FluentConditionBuilder()
            .string_matches("$mz")
            .at(0)
            .and_(FluentConditionBuilder().string_matches("$pe"))
            .and_(FluentConditionBuilder().string_matches("$suspicious")),
        )
        .then_rule("example_packed")
        .tagged("packed")
        .authored_by("Fluent API Demo")
        .mz_header()
        .with_condition_builder(
            lambda c: c.string_matches("$mz").at(0).and_(c.high_entropy()).and_(c.pe_is_exe()),
        )
        .then_build_file()
    )
