"""Ordering and canonicalization helpers for authoring actions."""

from __future__ import annotations

from yaraast.ast.rules import Tag
from yaraast.lsp.authoring_actions_common import replace_rule_text, require_rule_context
from yaraast.lsp.authoring_support import diff_preview, impact_title
from yaraast.lsp.safe_handler import lsp_safe_handler


@lsp_safe_handler
def _safe_parse(parser, text):
    return parser.parse(text)


def sort_strings_by_identifier(authoring, text: str, selection) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    ast = _safe_parse(authoring._parser, rule_context.text)
    if ast is None:
        return None
    if len(ast.rules) != 1:
        return None
    rule = ast.rules[0]
    if len(getattr(rule, "strings", [])) < 2:
        return None
    current_ids = [string_def.identifier for string_def in rule.strings]
    sorted_strings = sorted(rule.strings, key=lambda string_def: string_def.identifier)
    sorted_ids = [string_def.identifier for string_def in sorted_strings]
    if sorted_ids == current_ids:
        return None
    rule.strings = sorted_strings
    new_text = authoring._generator.generate(rule).rstrip("\n")
    return replace_rule_text(
        rule_context,
        new_text,
        f"Sort strings by identifier ({len(sorted_strings)} entries: {current_ids[0]}->{sorted_ids[0]})",
        f"First move: {current_ids[0]} -> {sorted_ids[0]}",
    )


def sort_meta_by_key(authoring, text: str, selection) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    ast = _safe_parse(authoring._parser, rule_context.text)
    if ast is None:
        return None
    if len(ast.rules) != 1:
        return None
    rule = ast.rules[0]
    meta = getattr(rule, "meta", None)
    if not meta:
        return None
    current_keys = [getattr(entry, "key", "") for entry in meta]
    sorted_meta = sorted(meta, key=lambda entry: getattr(entry, "key", ""))
    sorted_keys = [getattr(entry, "key", "") for entry in sorted_meta]
    if sorted_keys == current_keys:
        return None
    rule.meta = sorted_meta
    new_text = authoring._generator.generate(rule).rstrip("\n")
    return replace_rule_text(
        rule_context,
        new_text,
        f"Sort meta by key ({len(current_keys)} entries: {current_keys[0]}->{sorted_keys[0]})",
        f"First move: {current_keys[0]} -> {sorted_keys[0]}",
    )


def sort_tags_alphabetically(authoring, text: str, selection) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    ast = _safe_parse(authoring._parser, rule_context.text)
    if ast is None:
        return None
    if len(ast.rules) != 1:
        return None
    rule = ast.rules[0]
    tags = getattr(rule, "tags", [])
    if len(tags) < 2:
        return None
    current_names = [tag.name if hasattr(tag, "name") else str(tag) for tag in tags]
    sorted_names = sorted(current_names)
    if sorted_names == current_names:
        return None
    rule.tags = [Tag(name=name) for name in sorted_names]
    new_text = authoring._generator.generate(rule).rstrip("\n")
    return replace_rule_text(
        rule_context,
        new_text,
        f"Sort tags alphabetically ({len(sorted_names)} tags: {current_names[0]}->{sorted_names[0]})",
        f"First move: {current_names[0]} -> {sorted_names[0]}",
    )


def canonicalize_rule_structure(authoring, text: str, selection) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    original_ast = _safe_parse(authoring._parser, rule_context.text)
    if original_ast is None:
        return None
    if len(original_ast.rules) != 1:
        return None
    regenerated = authoring._advanced_generator.generate(original_ast.rules[0]).rstrip("\n")
    if regenerated.strip() == rule_context.text.strip():
        return None
    regenerated_ast = _safe_parse(authoring._parser, regenerated)
    if regenerated_ast is None:
        return None
    if len(regenerated_ast.rules) != 1:
        return None
    diff = authoring._differ.diff_asts(original_ast, regenerated_ast)
    if diff.logical_changes or diff.structural_changes or diff.added_rules or diff.removed_rules:
        return None
    return replace_rule_text(
        rule_context,
        regenerated,
        impact_title("Canonicalize rule structure", diff, regenerated),
        diff_preview(diff, "Canonical section/meta/string order"),
    )


def pretty_print_rule(authoring, text: str, selection) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    original_ast = _safe_parse(authoring._parser, rule_context.text)
    if original_ast is None:
        return None
    if len(original_ast.rules) != 1:
        return None
    regenerated = authoring._ast_formatter.format_ast(original_ast, style="pretty").rstrip("\n")
    if regenerated.strip() == rule_context.text.strip():
        return None
    regenerated_ast = _safe_parse(authoring._parser, regenerated)
    if regenerated_ast is None:
        return None
    if len(regenerated_ast.rules) != 1:
        return None
    diff = authoring._differ.diff_asts(original_ast, regenerated_ast)
    if diff.logical_changes or diff.structural_changes or diff.added_rules or diff.removed_rules:
        return None
    return replace_rule_text(
        rule_context,
        regenerated,
        impact_title("Pretty-print rule with AST formatter", diff, regenerated),
        diff_preview(diff, "Pretty printer rewrite validated by AST diff"),
    )
