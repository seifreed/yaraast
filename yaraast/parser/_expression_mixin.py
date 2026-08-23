"""Shared type contract for cooperating expression parser mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
    StringSetValue,
)
from yaraast.ast.expressions import Expression, FunctionCall, MemberAccess, RangeExpression
from yaraast.interfaces import IToken

from ._token_stream import TokenStreamMixin


class ExpressionMixinBase(TokenStreamMixin):
    """Declare cross-mixin methods supplied by the complete expression parser."""

    if TYPE_CHECKING:
        _contextual_local_identifiers: list[set[str]]

        def _parse_expression(self) -> Expression: ...

        def _parse_or_expression(self) -> Expression: ...

        def _parse_bitwise_or_expression(self) -> Expression: ...

        def _parse_primary_expression(self) -> Expression: ...

        def _parse_postfix_expression(self) -> Expression: ...

        def _parse_of_string_set(self) -> Expression: ...

        def _parse_of_expression(self, quantifier: str) -> OfExpression: ...

        def _parse_for_expression(
            self, start_token: IToken | None = None
        ) -> ForExpression | ForOfExpression: ...

        def _parse_at_postfix(self, expr: Expression) -> AtExpression: ...

        def _parse_in_postfix(self, expr: Expression) -> InExpression: ...

        def _of_string_set_kind(
            self, expr: StringSetValue, *, top_level: bool = False
        ) -> str | None: ...

        def _validate_static_of_quantifier(self, quantifier: Expression, token: IToken) -> None: ...

        def _validate_static_range_bounds(
            self, range_expr: RangeExpression, token: IToken
        ) -> None: ...

        def _static_integer_value(self, expr: Expression) -> int | None: ...

        def _build_member_function_call(
            self, expr: MemberAccess, args: list[Expression]
        ) -> FunctionCall: ...

        def _is_extern_rule_reference(
            self, rule_name: str, namespace: str | None = None
        ) -> bool: ...
