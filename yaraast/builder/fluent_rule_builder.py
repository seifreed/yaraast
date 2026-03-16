"""Enhanced fluent rule builder with comprehensive chaining support."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from yaraast.ast.rules import Rule
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.builder.fluent_rule_helpers import apply_last_string_modifier, combine_condition
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.builder.rule_builder import RuleBuilder

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import Expression


class FluentRuleBuilder:
    """Enhanced fluent builder for YARA rules with comprehensive chaining."""

    # Constants
    MZ_HEADER = "$mz"
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
        self._rule_builder.public()
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

    def mz_header(self, identifier: str = "$mz") -> Self:
        """Add MZ header string (alias for with_mz_header)."""
        return self.with_mz_header(identifier)

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
        apply_last_string_modifier(self._string_builders, "nocase")
        return self

    def ascii(self) -> Self:
        """Add ASCII modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "ascii")
        return self

    def wide(self) -> Self:
        """Add wide modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "wide")
        return self

    def fullword(self) -> Self:
        """Add fullword modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "fullword")
        return self

    def private_string(self) -> Self:
        """Add private modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "private")
        return self

    def xor(self, key: int | str | None = None) -> Self:
        """Add XOR modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "xor", key)
        return self

    def base64(self) -> Self:
        """Add base64 modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "base64")
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
        combined = combine_condition(self._rule_builder.get_condition(), condition_builder)
        return self.condition(combined)

    def for_large_files(self) -> Self:
        """Add large file condition (> 10MB)."""
        condition_builder = FluentConditionBuilder().large_file()
        combined = combine_condition(self._rule_builder.get_condition(), condition_builder)
        return self.condition(combined)

    def for_pe_files(self) -> Self:
        """Add PE file conditions."""
        # Add MZ header if not already present
        if not any(s.identifier in ["$mz", self.MZ_HEADER] for s in self._string_builders):
            self.with_mz_header(self.MZ_HEADER)

        condition_builder = FluentConditionBuilder().string_matches(self.MZ_HEADER).at(0)
        combined = combine_condition(self._rule_builder.get_condition(), condition_builder)
        return self.condition(combined)

    def for_executables(self) -> Self:
        """Add executable file conditions."""
        return self.for_pe_files().for_large_files()

    # Build method
    def build(self) -> Rule:
        """Build the rule."""
        self._rule_builder.add_string_definitions(
            [string_builder.build() for string_builder in self._string_builders],
        )

        rule = self._rule_builder.build()
        if isinstance(rule.meta, list):
            meta_dict: dict[str, object] = {}
            for item in rule.meta:
                if hasattr(item, "key") and hasattr(item, "value"):
                    meta_dict[item.key] = item.value
            rule.meta = meta_dict
        return rule


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


from yaraast.builder.fluent_file_builder import FluentYaraFileBuilder


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
