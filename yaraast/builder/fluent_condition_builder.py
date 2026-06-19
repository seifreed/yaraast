"""Enhanced fluent condition builder with comprehensive helpers."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, InExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    RangeExpression,
    StringIdentifier,
    UnaryExpression,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_helpers import (
    build_entropy_compare,
    build_of_expression,
    build_string_set,
    make_filesize_compare,
    make_integer_literal,
    make_string_count_compare,
    validate_string_reference,
)
from yaraast.errors import ValidationError


class FluentConditionBuilder(ConditionBuilder):
    """Enhanced fluent condition builder with common pattern helpers."""

    def __init__(self, expr: Expression | None = None) -> None:
        super().__init__(expr)

    # Enhanced quantifier methods
    def any_of_them(self) -> FluentConditionBuilder:
        """Any of them - common pattern."""
        return FluentConditionBuilder(build_of_expression("any", Identifier(name="them")))

    def all_of_them(self) -> FluentConditionBuilder:
        """All of them - common pattern."""
        return FluentConditionBuilder(build_of_expression("all", Identifier(name="them")))

    def not_them(self) -> FluentConditionBuilder:
        """Not any of them - negated pattern."""
        return FluentConditionBuilder(
            UnaryExpression(
                operator="not",
                operand=build_of_expression("any", Identifier(name="them")),
            ),
        )

    def one_of(self, *strings: str) -> FluentConditionBuilder:
        """Exactly one of the specified strings."""
        return self.between_n_and_m_of(1, 1, *strings)

    def two_of(self, *strings: str) -> FluentConditionBuilder:
        """Exactly two of the specified strings."""
        return self.between_n_and_m_of(2, 2, *strings)

    def three_of(self, *strings: str) -> FluentConditionBuilder:
        """Exactly three of the specified strings."""
        return self.between_n_and_m_of(3, 3, *strings)

    def at_least_n_of(self, n: int, *strings: str) -> FluentConditionBuilder:
        """At least N of the specified strings."""
        self._validate_quantifier_count("Minimum", n)
        string_set = build_string_set(*strings)
        if n == 0:
            return FluentConditionBuilder(BooleanLiteral(value=True))
        return FluentConditionBuilder(build_of_expression(n, string_set))

    def at_most_n_of(self, n: int, *strings: str) -> FluentConditionBuilder:
        """At most N of the specified strings."""
        self._validate_quantifier_count("Maximum", n)
        string_set = build_string_set(*strings)
        if n == 0:
            return FluentConditionBuilder(build_of_expression("none", string_set))
        return FluentConditionBuilder(
            UnaryExpression(
                operator="not",
                operand=build_of_expression(n + 1, string_set),
            ),
        )

    def between_n_and_m_of(
        self,
        min_n: int,
        max_m: int,
        *strings: str,
    ) -> FluentConditionBuilder:
        """Between N and M of the specified strings."""
        self._validate_quantifier_count("Minimum", min_n)
        self._validate_quantifier_count("Maximum", max_m)
        if min_n > max_m:
            msg = f"Minimum count {min_n} cannot exceed maximum {max_m}"
            raise ValidationError(msg)
        if min_n == 0:
            return self.at_most_n_of(max_m, *strings)

        string_set = build_string_set(*strings)
        return FluentConditionBuilder(
            BinaryExpression(
                left=build_of_expression(min_n, string_set),
                operator="and",
                right=UnaryExpression(
                    operator="not",
                    operand=build_of_expression(max_m + 1, string_set),
                ),
            ),
        )

    # String-specific helpers
    def string_matches(self, string_id: str) -> FluentConditionBuilder:
        """String matches (shorthand for string identifier)."""
        validate_string_reference(string_id)
        return FluentConditionBuilder(StringIdentifier(name=string_id))

    def string_count_eq(self, string_id: str, count: int) -> FluentConditionBuilder:
        """String count equals N."""
        return FluentConditionBuilder(make_string_count_compare(string_id, "==", count))

    def string_count_gt(self, string_id: str, count: int) -> FluentConditionBuilder:
        """String count greater than N."""
        return FluentConditionBuilder(make_string_count_compare(string_id, ">", count))

    def string_count_ge(self, string_id: str, count: int) -> FluentConditionBuilder:
        """String count greater than or equal to N."""
        return FluentConditionBuilder(make_string_count_compare(string_id, ">=", count))

    def string_at_entrypoint(self, string_id: str) -> FluentConditionBuilder:
        """String at entrypoint."""
        validate_string_reference(string_id)
        return FluentConditionBuilder(
            AtExpression(string_id=string_id, offset=Identifier(name="entrypoint")),
        )

    def string_at_offset(self, string_id: str, offset: int) -> FluentConditionBuilder:
        """String at specific offset."""
        validate_string_reference(string_id)
        return FluentConditionBuilder(
            AtExpression(string_id=string_id, offset=make_integer_literal(offset)),
        )

    def string_in_first_kb(self, string_id: str) -> FluentConditionBuilder:
        """String in first 1KB of file."""
        validate_string_reference(string_id)
        return FluentConditionBuilder(
            InExpression(
                subject=string_id,
                range=RangeExpression(
                    low=IntegerLiteral(value=0),
                    high=IntegerLiteral(value=1024),
                ),
            ),
        )

    def string_in_last_kb(self, string_id: str) -> FluentConditionBuilder:
        """String in last 1KB of file."""
        validate_string_reference(string_id)
        return FluentConditionBuilder(
            InExpression(
                subject=string_id,
                range=RangeExpression(
                    low=BinaryExpression(
                        left=Identifier(name="filesize"),
                        operator="-",
                        right=IntegerLiteral(value=1024),
                    ),
                    high=Identifier(name="filesize"),
                ),
            ),
        )

    # File property helpers
    def filesize_eq(self, size: int) -> FluentConditionBuilder:
        """File size equals specific value."""
        return FluentConditionBuilder(make_filesize_compare("==", size))

    def filesize_gt(self, size: int) -> FluentConditionBuilder:
        """File size greater than."""
        return FluentConditionBuilder(make_filesize_compare(">", size))

    def filesize_lt(self, size: int) -> FluentConditionBuilder:
        """File size less than."""
        return FluentConditionBuilder(make_filesize_compare("<", size))

    def filesize_between(self, min_size: int, max_size: int) -> FluentConditionBuilder:
        """File size between min and max."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=make_filesize_compare(">=", min_size),
                operator="and",
                right=make_filesize_compare("<=", max_size),
            ),
        )

    def large_file(self) -> FluentConditionBuilder:
        """Large file (> 10MB)."""
        return self.filesize_gt(10 * 1024 * 1024)

    def pe_is_dll(self) -> FluentConditionBuilder:
        """PE is DLL."""
        return FluentConditionBuilder(
            FunctionCall(function="pe.is_dll", arguments=[]),
        )

    def pe_is_exe(self) -> FluentConditionBuilder:
        """PE is executable (not DLL)."""
        return FluentConditionBuilder(
            UnaryExpression(
                operator="not",
                operand=FunctionCall(function="pe.is_dll", arguments=[]),
            ),
        )

    def pe_section_count_eq(self, count: int) -> FluentConditionBuilder:
        """PE section count equals."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=MemberAccess(
                    object=Identifier(name="pe"),
                    member="number_of_sections",
                ),
                operator="==",
                right=make_integer_literal(count),
            ),
        )

    def entropy_gt(
        self,
        offset: int,
        size: int,
        threshold: float,
    ) -> FluentConditionBuilder:
        """Entropy greater than threshold."""
        return FluentConditionBuilder(build_entropy_compare(">", offset, size, threshold))

    def high_entropy(self, offset: int = 0, size: int = 1024) -> FluentConditionBuilder:
        """High entropy section (> 7.0)."""
        return self.entropy_gt(offset, size, 7.0)

    def _validate_quantifier_count(self, name: str, count: int) -> None:
        make_integer_literal(count)
        if count < 0:
            msg = f"{name} count must be non-negative, got {count}"
            raise ValidationError(msg)

    # Factory methods
    @staticmethod
    def create() -> FluentConditionBuilder:
        """Create empty fluent condition builder."""
        return FluentConditionBuilder()

    @staticmethod
    def match_string(string_id: str) -> FluentConditionBuilder:
        """Create condition matching a string."""
        validate_string_reference(string_id)
        return FluentConditionBuilder(StringIdentifier(name=string_id))

    @staticmethod
    def always_true() -> FluentConditionBuilder:
        """Always true condition."""
        return FluentConditionBuilder(BooleanLiteral(value=True))


# Convenience functions
