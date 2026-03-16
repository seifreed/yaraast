"""Shared helpers for authoring action rewrites and structural edits."""

from __future__ import annotations

from lsprotocol.types import Position, Range, TextEdit

from yaraast.lsp.authoring_support import RuleContext, get_rule_context


def require_rule_context(text: str, current_line: int) -> RuleContext | None:
    """Return the enclosing rule context for the current line."""
    return get_rule_context(text, current_line)


def replace_rule_text(
    rule_context: RuleContext,
    new_text: str,
    title: str,
    preview: str,
):
    """Build a TextEdit replacing the current rule body."""
    from yaraast.lsp.authoring_actions import StructuralEdit

    return StructuralEdit(
        title=title,
        edit=TextEdit(
            range=Range(
                start=Position(line=rule_context.start, character=0),
                end=Position(
                    line=rule_context.end,
                    character=len(rule_context.lines[rule_context.end]),
                ),
            ),
            new_text=new_text,
        ),
        preview=preview,
    )
