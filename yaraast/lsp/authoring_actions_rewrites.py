"""Rule rewrite helpers for authoring actions."""

from __future__ import annotations

from yaraast.lsp.authoring_actions_common import replace_rule_text, require_rule_context
from yaraast.lsp.authoring_rewriters import OfThemTransformer, StringReferenceRewriter
from yaraast.lsp.authoring_support import diff_preview, impact_title, string_signature
from yaraast.lsp.safe_handler import lsp_safe_handler


@lsp_safe_handler
def _safe_parse(parser, text):
    return parser.parse(text)


@lsp_safe_handler
def _safe_roundtrip(roundtrip, text):
    original_ast, serialized = roundtrip.parse_and_serialize(text)
    reconstructed_ast, regenerated = roundtrip.deserialize_and_generate(serialized)
    return original_ast, reconstructed_ast, regenerated


def optimize_rule(authoring, text: str, selection) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    ast = _safe_parse(authoring._parser, rule_context.text)
    if ast is None:
        return None
    if len(ast.rules) != 1:
        return None
    rule = ast.rules[0]
    if getattr(rule, "condition", None) is None:
        return None
    optimized_rule = authoring._optimizer.optimize_rule(rule)
    new_text = authoring._generator.generate(optimized_rule).rstrip("\n")
    if new_text.strip() == rule_context.text.strip():
        return None
    return replace_rule_text(
        rule_context, new_text, "Simplify rule condition", "Optimize boolean/expression structure"
    )


def roundtrip_rewrite_rule(authoring, text: str, selection) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    result = _safe_roundtrip(authoring._roundtrip, rule_context.text)
    if result is None:
        return None
    original_ast, reconstructed_ast, regenerated = result
    diff = authoring._differ.diff_asts(original_ast, reconstructed_ast)
    if diff.logical_changes or diff.structural_changes or diff.added_rules or diff.removed_rules:
        return None
    regenerated = regenerated.rstrip("\n")
    if regenerated.strip() == rule_context.text.strip():
        return None
    return replace_rule_text(
        rule_context,
        regenerated,
        impact_title("Normalize rule via round-trip", diff, regenerated),
        diff_preview(diff, "Round-trip rewrite validated by AST diff"),
    )


def deduplicate_identical_strings(authoring, text: str, selection) -> object | None:
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
    seen: dict[tuple[object, ...], str] = {}
    replacements: dict[str, str] = {}
    unique_strings = []
    changed = False
    for string_def in rule.strings:
        signature = string_signature(string_def)
        existing = seen.get(signature)
        if existing is None:
            seen[signature] = string_def.identifier
            unique_strings.append(string_def)
            continue
        replacements[string_def.identifier] = existing
        changed = True
    if not changed:
        return None
    rule.strings = unique_strings
    if rule.condition is not None:
        rule.condition = StringReferenceRewriter(replacements).visit(rule.condition)
    new_text = authoring._generator.generate(rule).rstrip("\n")
    preview = ", ".join(f"{old}->{new}" for old, new in list(replacements.items())[:2])
    return replace_rule_text(
        rule_context,
        new_text,
        f"Deduplicate identical strings ({len(replacements)} merged: {preview})",
        f"Merged duplicates: {preview}",
    )


def rewrite_of_them(authoring, text: str, selection, *, mode: str, title: str) -> object | None:
    rule_context = require_rule_context(text, selection.start.line)
    if rule_context is None:
        return None
    ast = _safe_parse(authoring._parser, rule_context.text)
    if ast is None:
        return None
    if len(ast.rules) != 1:
        return None
    rule = ast.rules[0]
    string_ids = [string_def.identifier for string_def in getattr(rule, "strings", [])]
    if not string_ids or rule.condition is None:
        return None
    original = authoring._generator.generate(rule).rstrip("\n")
    rule.condition = OfThemTransformer(string_ids, mode).visit(rule.condition)
    rewritten = authoring._generator.generate(rule).rstrip("\n")
    if rewritten.strip() == original.strip():
        return None
    preview = len(string_ids)
    return replace_rule_text(
        rule_context,
        rewritten,
        f"{title} ({preview} strings, {string_ids[0]}...)",
        f"Rewrite string set using {preview} strings",
    )
