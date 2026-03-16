"""Rule-level validation mixin for YARA-L."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import YaraLFile, YaraLRule


class RuleValidationMixin:
    """Validate file/rule-level structure and cross-section references."""

    def visit_yaral_file(self, node: YaraLFile) -> None:
        """Validate YARA-L file."""
        if not node.rules:
            self._add_warning("file", "Empty YARA-L file")

        rule_names = set()
        for rule in node.rules:
            if rule.name in rule_names:
                self._add_error(
                    "file",
                    f"Duplicate rule name: {rule.name}",
                    "Use unique names for each rule",
                )
            rule_names.add(rule.name)
            self.visit(rule)

    def visit_yaral_rule(self, node: YaraLRule) -> None:
        """Validate YARA-L rule."""
        self.current_rule = node.name
        self.defined_events.clear()
        self.used_events.clear()
        self.defined_match_vars.clear()
        self.used_match_vars.clear()
        self.defined_outcome_vars.clear()

        if not node.name:
            self._add_error("rule", "Rule must have a name")
        elif not node.name[0].isalpha() and node.name[0] != "_":
            self._add_error(
                "rule",
                f"Rule name '{node.name}' must start with letter or underscore",
                "Use valid identifier format",
            )

        if not node.events:
            self._add_error(
                "rule",
                "Rule must have an events section",
                "Add 'events:' section to define event patterns",
            )

        if not node.condition:
            self._add_error(
                "rule",
                "Rule must have a condition section",
                "Add 'condition:' section to define matching conditions",
            )

        if node.meta:
            self._validate_meta_section(node.meta)

        if node.events:
            self.visit(node.events)

        if node.match:
            self._validate_match_section(node.match)

        if node.condition:
            self._validate_condition_section(node.condition)
            self.visit(node.condition)

        if node.outcome:
            self._validate_outcome_section(node.outcome)

        if node.options:
            self._validate_options_section(node.options)

        self._validate_cross_sections()

    def _validate_cross_sections(self) -> None:
        """Validate cross-section references."""
        undefined_events = self.used_events - self.defined_events
        undefined_events = {
            e
            for e in undefined_events
            if e not in self.defined_outcome_vars and f"${e}" not in self.defined_outcome_vars
        }
        for event in undefined_events:
            self._add_error(
                "condition",
                f"Undefined event variable: {event}",
                "Define event in events section",
            )

        unused_events = self.defined_events - self.used_events
        for event in unused_events:
            self._add_warning(
                "events",
                f"Unused event variable: {event}",
                "Remove unused event or use it in condition",
            )

        unused_match_vars = self.defined_match_vars - self.used_match_vars
        for var in unused_match_vars:
            self._add_warning(
                "match",
                f"Unused match variable: {var}",
                "Remove unused variable or use it in outcome",
            )
