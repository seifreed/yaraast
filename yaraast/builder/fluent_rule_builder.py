"""Enhanced fluent rule builder with comprehensive chaining support."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from yaraast.ast.rules import Rule
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.builder.fluent_rule_helpers import apply_last_string_modifier, combine_condition
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.builder.rule_builder import RuleBuilder
from yaraast.builder.string_identifier_validation import normalize_string_identifier
from yaraast.errors import ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable

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
    def private(self) -> Self:
        """Mark rule as private."""
        self._rule_builder.private()
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

    def authored_by(self, author: str) -> Self:
        """Set author."""
        self._rule_builder.with_meta("author", author)
        return self

    def described_as(self, description: str) -> Self:
        """Set description."""
        self._rule_builder.with_meta("description", description)
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
            builder = FluentStringBuilder(identifier_or_builder).literal(value)
            self._string_builders.append(builder)
        elif isinstance(identifier_or_builder, FluentStringBuilder):
            # Builder case
            normalize_string_identifier(identifier_or_builder.identifier)
            self._string_builders.append(identifier_or_builder)
        else:
            msg = "Either provide (identifier, value) or a FluentStringBuilder"
            raise ValidationError(
                msg,
            )
        return self

    def text_string(self, identifier: str, content: str) -> Self:
        """Add a text string."""
        builder = FluentStringBuilder(identifier).literal(content)
        return self.with_string(builder)

    def hex_string(self, identifier: str, pattern: str) -> Self:
        """Add a hex string."""
        builder = FluentStringBuilder(identifier).hex(pattern)
        return self.with_string(builder)

    def regex_string(self, identifier: str, pattern: str) -> Self:
        """Add a regex string."""
        builder = FluentStringBuilder(identifier).regex(pattern)
        return self.with_string(builder)

    # Common string patterns
    def mz_header(self, identifier: str = "$mz") -> Self:
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
            FluentStringBuilder.string(identifier).ip_pattern(),
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

    def xor(self, key: int | str | None = None) -> Self:
        """Add XOR modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "xor", key)
        return self

    def base64(self) -> Self:
        """Add base64 modifier to the most recent string."""
        apply_last_string_modifier(self._string_builders, "base64")
        return self

    # Condition methods
    def condition(self, condition: str | Expression | ConditionBuilder) -> Self:
        """Set the rule condition."""
        if isinstance(condition, ConditionBuilder):
            self._rule_builder.with_condition(condition.build())
        else:
            self._rule_builder.with_condition(condition)
        return self

    def matches_any(self) -> Self:
        """Condition: any of them."""
        return self.condition("any of them")

    def matches_any_of(self, *strings: str) -> Self:
        """Condition: any of specified strings."""
        builder = FluentConditionBuilder().any_of(*strings)
        return self.condition(builder)

    def with_condition_builder(
        self,
        builder_func: Callable[[FluentConditionBuilder], ConditionBuilder],
    ) -> Self:
        """Set condition using a builder function."""
        if not callable(builder_func):
            msg = "Condition builder callback must be callable"
            raise TypeError(msg)
        condition_builder = FluentConditionBuilder()
        result = builder_func(condition_builder)
        if not isinstance(result, ConditionBuilder):
            msg = "Condition builder callback must return a ConditionBuilder"
            raise ValidationError(msg)
        return self.condition(result)

    # File property conditions
    def for_pe_files(self) -> Self:
        """Add PE file conditions."""
        # Add MZ header if not already present
        if not any(s.identifier in ["$mz", self.MZ_HEADER] for s in self._string_builders):
            self.mz_header(self.MZ_HEADER)

        condition_builder = FluentConditionBuilder().string_matches(self.MZ_HEADER).at(0)
        combined = combine_condition(self._rule_builder.get_condition(), condition_builder)
        return self.condition(combined)

    # Build method
    def build(self) -> Rule:
        """Build the rule."""
        original_strings = list(self._rule_builder._strings)
        built_strings = [string_builder.build() for string_builder in self._string_builders]
        self._rule_builder._strings = [*original_strings, *built_strings]
        try:
            return self._rule_builder.build()
        finally:
            self._rule_builder._strings = original_strings
