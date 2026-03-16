"""Match section validation mixin for YARA-L."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import MatchSection, MatchVariable, TimeWindow


class MatchValidationMixin:
    """Validate match variables and time windows."""

    def _validate_match_section(self, node: MatchSection) -> None:
        """Validate match section."""
        if not node.variables:
            self._add_warning(
                "match",
                "Match section has no variables",
                "Define match variables for correlation",
            )

        for var in node.variables:
            if var.variable in self.defined_match_vars:
                self._add_error(
                    "match",
                    f"Duplicate match variable: {var.variable}",
                    "Use unique match variable names",
                )
            self.defined_match_vars.add(var.variable)

            if var.time_window.unit not in self.VALID_TIME_UNITS:
                self._add_error(
                    "match",
                    f"Invalid time unit: {var.time_window.unit}",
                    f"Use one of: {', '.join(self.VALID_TIME_UNITS)}",
                )
            if var.time_window.duration <= 0:
                self._add_error(
                    "match",
                    "Time window duration must be positive",
                    "Use positive duration value",
                )
            elif var.time_window.duration > 30 and var.time_window.unit in [
                "d",
                "days",
            ]:
                self._add_warning(
                    "match",
                    f"Large time window: {var.time_window.duration} {var.time_window.unit}",
                    "Consider using smaller time windows for better performance",
                )

    def visit_yaral_match_section(self, node: MatchSection) -> None:
        self._validate_match_section(node)
        for var in node.variables:
            self.visit(var)

    def visit_yaral_match_variable(self, node: MatchVariable) -> None:
        self.defined_match_vars.add(node.variable)

    def visit_yaral_time_window(self, node: TimeWindow) -> None:
        if node.unit not in self.VALID_TIME_UNITS:
            self._add_error(
                "match",
                f"Invalid time unit '{node.unit}'",
                f"Use one of: {', '.join(self.VALID_TIME_UNITS)}",
            )
