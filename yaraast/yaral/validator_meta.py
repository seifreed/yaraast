"""Meta-section validation mixin for YARA-L."""

from __future__ import annotations

from typing import Any


class MetaValidationMixin:
    """Validate meta sections and entries."""

    def _validate_meta_section(self, node: Any) -> None:
        """Validate meta section."""
        required_meta = ["author", "description"]
        found_keys = set()

        if hasattr(node, "entries"):
            for entry in node.entries:
                found_keys.add(entry.key)

                if entry.key == "severity" and isinstance(entry.value, str):
                    valid_severities = [
                        "informational",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ]
                    if entry.value.lower() not in valid_severities:
                        self._add_warning(
                            "meta",
                            f"Invalid severity value: {entry.value}",
                            f"Use one of: {', '.join(valid_severities)}",
                        )

        for key in required_meta:
            if key not in found_keys:
                self._add_warning(
                    "meta",
                    f"Missing recommended meta field: {key}",
                    f"Add '{key}' to meta section",
                )

    def visit_yaral_meta_section(self, node: Any) -> None:
        self._validate_meta_section(node)

    def visit_yaral_meta_entry(self, node: Any) -> None:
        return

    def visit_yaral_regex_pattern(self, node) -> None:
        return

    def visit_yaral_cidr_expression(self, node) -> None:
        return

    def visit_yaral_function_call(self, node) -> None:
        return
