"""Implementation helpers behind the AuthoringActions facade."""

from __future__ import annotations

from dataclasses import dataclass

from lsprotocol.types import Range, TextEdit

from yaraast.lsp.authoring_actions_basic import (  # noqa: F401
    convert_plain_string_to_hex,
    create_missing_string,
    normalize_string_modifiers,
)
from yaraast.lsp.authoring_actions_common import replace_rule_text, require_rule_context
from yaraast.lsp.authoring_actions_rewrites import (
    deduplicate_identical_strings as rewrite_deduplicate_identical_strings,
)
from yaraast.lsp.authoring_actions_rewrites import optimize_rule as rewrite_optimize_rule
from yaraast.lsp.authoring_actions_rewrites import rewrite_of_them as rewrite_of_them_action
from yaraast.lsp.authoring_actions_rewrites import roundtrip_rewrite_rule as rewrite_roundtrip_rule
from yaraast.lsp.authoring_actions_sorting import (
    canonicalize_rule_structure as sort_canonicalize_rule_structure,
)
from yaraast.lsp.authoring_actions_sorting import pretty_print_rule as sort_pretty_print_rule
from yaraast.lsp.authoring_actions_sorting import sort_meta_by_key as sort_sort_meta_by_key
from yaraast.lsp.authoring_actions_sorting import (
    sort_strings_by_identifier as sort_sort_strings_by_identifier,
)
from yaraast.lsp.authoring_actions_sorting import (
    sort_tags_alphabetically as sort_sort_tags_alphabetically,
)
from yaraast.lsp.authoring_support import RuleContext


@dataclass(slots=True)
class StructuralEdit:
    """Named structural edit built from the current document."""

    title: str
    edit: TextEdit
    preview: str | None = None


def optimize_rule(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return rewrite_optimize_rule(authoring, text, selection)


def roundtrip_rewrite_rule(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return rewrite_roundtrip_rule(authoring, text, selection)


def deduplicate_identical_strings(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return rewrite_deduplicate_identical_strings(authoring, text, selection)


def sort_strings_by_identifier(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return sort_sort_strings_by_identifier(authoring, text, selection)


def sort_meta_by_key(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return sort_sort_meta_by_key(authoring, text, selection)


def sort_tags_alphabetically(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return sort_sort_tags_alphabetically(authoring, text, selection)


def canonicalize_rule_structure(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return sort_canonicalize_rule_structure(authoring, text, selection)


def pretty_print_rule(authoring, text: str, selection: Range) -> StructuralEdit | None:
    return sort_pretty_print_rule(authoring, text, selection)


def rewrite_of_them(
    authoring, text: str, selection: Range, *, mode: str, title: str
) -> StructuralEdit | None:
    return rewrite_of_them_action(authoring, text, selection, mode=mode, title=title)


def _require_rule_context(text: str, current_line: int) -> RuleContext | None:
    return require_rule_context(text, current_line)


def _replace_rule_text(
    rule_context: RuleContext,
    new_text: str,
    title: str,
    preview: str,
) -> StructuralEdit:
    return replace_rule_text(rule_context, new_text, title, preview)
