"""Refactor and authoring actions for LSP code actions."""

from __future__ import annotations

from lsprotocol.types import CodeAction, CodeActionKind, Position, Range, WorkspaceEdit

from yaraast.lsp.utils import get_word_at_position


class RefactorCodeActionMixin:
    """Helpers for refactor-oriented code actions."""

    def _get_refactoring_actions(
        self,
        text: str,
        range_: Range,
        uri: str,
    ) -> list[CodeAction]:
        """Get refactoring actions for the given range."""
        actions = []

        get_word_at_position(text, range_.start)

        if self._is_in_condition(text, range_.start):
            actions.append(
                CodeAction(
                    title="Extract to rule",
                    kind=CodeActionKind.RefactorExtract,
                )
            )

        for structural_edit in [
            self.authoring.normalize_string_modifiers(text, range_),
            self.authoring.convert_plain_string_to_hex(text, range_),
            self.authoring.optimize_rule(text, range_),
            self.authoring.roundtrip_rewrite_rule(text, range_),
            self.authoring.deduplicate_identical_strings(text, range_),
            self.authoring.sort_strings_by_identifier(text, range_),
            self.authoring.sort_meta_by_key(text, range_),
            self.authoring.sort_tags_alphabetically(text, range_),
            self.authoring.canonicalize_rule_structure(text, range_),
            self.authoring.pretty_print_rule(text, range_),
            self.authoring.expand_of_them(text, range_),
            self.authoring.compress_of_them(text, range_),
        ]:
            if structural_edit is not None:
                actions.append(self._authoring_action(uri, structural_edit))

        return actions

    def _authoring_action(self, uri: str, structural_edit) -> CodeAction:
        data = {"provider": "authoring"}
        if getattr(structural_edit, "preview", None):
            data["preview"] = structural_edit.preview
        return CodeAction(
            title=structural_edit.title,
            kind=CodeActionKind.RefactorRewrite,
            edit=WorkspaceEdit(changes={uri: [structural_edit.edit]}),
            data=data,
        )

    def _is_in_condition(self, text: str, position: Position) -> bool:
        """Check if position is inside a condition section."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return False

        for i in range(position.line, -1, -1):
            if "condition:" in lines[i]:
                return True
            if "rule " in lines[i] or "strings:" in lines[i]:
                return False

        return False
