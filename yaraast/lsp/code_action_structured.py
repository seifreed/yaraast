"""Structured diagnostic helpers for LSP code actions."""

from __future__ import annotations

from collections.abc import Mapping

from lsprotocol.types import (
    CodeAction,
    CodeActionKind,
    Diagnostic,
    Position,
    Range,
    TextEdit,
    WorkspaceEdit,
)


class StructuredCodeActionMixin:
    """Helpers for quick fixes driven by structured diagnostic payloads."""

    def _get_diagnostic_data(self, diagnostic: Diagnostic) -> Mapping[str, object] | None:
        data = getattr(diagnostic, "data", None)
        if isinstance(data, Mapping):
            return data
        return None

    def _create_structured_actions(self, diagnostic: Diagnostic, uri: str) -> list[CodeAction]:
        """Create quick fixes from structured diagnostic payloads."""
        data = getattr(diagnostic, "data", None)
        if not isinstance(data, dict):
            return []

        patches = data.get("patches")
        if not isinstance(patches, list) or not patches:
            return []

        actions: list[CodeAction] = []
        for idx, patch in enumerate(patches, start=1):
            if not isinstance(patch, Mapping):
                continue
            patch_range = self._coerce_range(patch.get("range"))
            replacement = patch.get("replacement")
            if not isinstance(patch_range, Range) or not isinstance(replacement, str):
                continue

            title = diagnostic.message.split("\n", 1)[0]
            if len(patches) > 1:
                title = f"{title} ({idx})"

            actions.append(
                CodeAction(
                    title=f"Fix: {title}",
                    kind=CodeActionKind.QuickFix,
                    edit=WorkspaceEdit(
                        changes={
                            uri: [
                                TextEdit(
                                    range=patch_range,
                                    new_text=replacement,
                                )
                            ]
                        }
                    ),
                    diagnostics=[diagnostic],
                )
            )

        return actions

    def _coerce_range(self, value: object) -> Range | None:
        if isinstance(value, Range):
            return value
        if not isinstance(value, Mapping):
            return None
        start = value.get("start")
        end = value.get("end")
        if not isinstance(start, Mapping) or not isinstance(end, Mapping):
            return None
        start_line = start.get("line")
        start_char = start.get("character")
        end_line = end.get("line")
        end_char = end.get("character")
        if not all(isinstance(v, int) for v in [start_line, start_char, end_line, end_char]):
            return None
        return Range(
            start=Position(line=start_line, character=start_char),
            end=Position(line=end_line, character=end_char),
        )
