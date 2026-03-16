"""Options section validation mixin for YARA-L."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import OptionsSection


class OptionsValidationMixin:
    """Validate options section."""

    def _validate_options_section(self, node: OptionsSection) -> None:
        """Validate options section."""
        valid_options = [
            "allow_zero_values",
            "case_sensitive",
            "max_events",
            "max_matches",
            "timeout",
            "output_format",
        ]

        if hasattr(node, "options"):
            for key in node.options:
                if key not in valid_options:
                    self._add_warning(
                        "options",
                        f"Unknown option: {key}",
                        f"Valid options: {', '.join(valid_options)}",
                    )

    def visit_yaral_options_section(self, node: OptionsSection) -> None:
        self._validate_options_section(node)
