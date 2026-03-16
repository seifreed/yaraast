"""Expression parsing helpers."""

from __future__ import annotations

from yaraast.ast.conditions import Condition

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

    def _parse_condition(self) -> Condition:
        """Parse condition expression."""
        return self._parse_or_expression()
