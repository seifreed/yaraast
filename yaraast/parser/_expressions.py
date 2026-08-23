"""Expression parsing helpers."""

from __future__ import annotations

from yaraast.ast.expressions import Expression

from ._expressions_binary import ExpressionBinaryMixin
from ._expressions_for import ExpressionForMixin
from ._expressions_postfix import ExpressionPostfixMixin
from ._expressions_primary import ExpressionPrimaryMixin


class ExpressionParsingMixin(
    ExpressionBinaryMixin,
    ExpressionPostfixMixin,
    ExpressionPrimaryMixin,
    ExpressionForMixin,
):
    """Mixin with expression parsing helpers."""

    def _parse_condition(self) -> Expression:
        """Parse condition expression."""
        return self._parse_or_expression()
