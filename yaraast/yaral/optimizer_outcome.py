"""Outcome/match/options optimization mixin for YARA-L optimizer."""

from __future__ import annotations

from typing import Any

from yaraast.yaral.ast_nodes import MatchSection, OutcomeAssignment, OutcomeSection


class YaraLOptimizerOutcomeMixin:
    """Outcome, match, and options optimization methods."""

    def _optimize_match_section(self, match: MatchSection) -> MatchSection:
        if not match:
            return match

        optimized_vars = []
        for var in match.variables:
            var_name = getattr(var, "variable", getattr(var, "name", None))
            if var_name and self._is_match_var_used(var_name):
                if hasattr(var, "time_window") and var.time_window:
                    var.time_window = self._optimize_time_window(var.time_window)
                optimized_vars.append(var)

        return MatchSection(variables=optimized_vars)

    def _optimize_time_window(self, window: Any) -> Any:
        if hasattr(window, "duration") and hasattr(window, "unit"):
            duration = window.duration
            unit = window.unit

            if unit in ["s", "seconds"] and duration >= 3600:
                window.duration = duration // 3600
                window.unit = "h"
                self.stats.time_windows_optimized += 1
            elif unit in ["m", "minutes"] and duration >= 1440:
                window.duration = duration // 1440
                window.unit = "d"
                self.stats.time_windows_optimized += 1

        return window

    def _optimize_outcome_section(self, outcome: OutcomeSection) -> OutcomeSection:
        if not outcome:
            return outcome

        if hasattr(outcome, "assignments"):
            return outcome

        optimized_vars = {}
        if hasattr(outcome, "variables"):
            for var_name, var_expr in outcome.variables.items():
                if self._is_outcome_var_used(var_name) or var_name in [
                    "risk_score",
                    "severity",
                ]:
                    optimized_vars[var_name] = var_expr

        return OutcomeSection(
            assignments=[
                OutcomeAssignment(variable=var_name, expression=var_expr)
                for var_name, var_expr in optimized_vars.items()
            ]
        )

    def _optimize_options(self, options: Any) -> Any:
        if not options:
            return options

        if hasattr(options, "options"):
            if "max_events" not in options.options:
                options.options["max_events"] = 10000

            if "timeout" not in options.options:
                options.options["timeout"] = "5m"

        return options
