"""Enhanced fluent condition builder with comprehensive helpers."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Expression,
    FunctionCall,
    Identifier,
    MemberAccess,
    StringIdentifier,
    UnaryExpression,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.fluent_condition_helpers import (
    build_entropy_compare,
    make_filesize_compare,
    make_integer_literal,
    make_string_count_compare,
    validate_string_reference,
)


class FluentConditionBuilder(ConditionBuilder):
    """Enhanced fluent condition builder with common pattern helpers."""

    def __init__(self, expr: Expression | None = None) -> None:
        super().__init__(expr)

    # Enhanced quantifier methods
    def one_of(self, *strings: str) -> FluentConditionBuilder:
        """Exactly one of the specified strings."""
        return FluentConditionBuilder(super().n_of(1, *strings).build())

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
