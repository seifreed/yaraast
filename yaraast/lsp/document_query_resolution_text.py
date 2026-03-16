"""Text fallback helpers for LSP symbol resolution."""

from __future__ import annotations

from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.structure import make_range
from yaraast.lsp.utils import get_word_at_position


def resolve_symbol_from_text_fallback(
    ctx,
    position,
    *,
    allow_generic_identifier: bool = True,
) -> ResolvedSymbol | None:
    module_member = find_module_member_at_position(ctx, position)
    if module_member is not None:
        return module_member
    word, word_range = get_word_at_position(ctx.text, position)
    if not word:
        return None
    if word.startswith(("$", "#", "@", "!")):
        base_identifier = word.lstrip("#@!")
        if not base_identifier.startswith("$"):
            base_identifier = f"${base_identifier}"
        return ResolvedSymbol(ctx.uri, word, base_identifier, "string", word_range)
    if "." in word:
        return ResolvedSymbol(ctx.uri, word, word, "module_member", word_range)
    if ctx.find_rule_definition(word) is not None:
        return ResolvedSymbol(ctx.uri, word, word, "rule", word_range)
    if not allow_generic_identifier:
        return None
    return ResolvedSymbol(ctx.uri, word, word, "identifier", word_range)


def find_module_member_at_position(ctx, position) -> ResolvedSymbol | None:
    word, word_range = get_word_at_position(ctx.text, position)
    dotted_from_word = resolve_dotted_word(ctx, word, word_range)
    if dotted_from_word is not None:
        return dotted_from_word
    if position.line < 0 or position.line >= len(ctx.lines):
        return None
    line = ctx.lines[position.line]
    imported_modules = [symbol.name for symbol in ctx.symbols() if symbol.kind == "import"]
    for module_name in imported_modules:
        needle = f"{module_name}."
        start = 0
        while True:
            start = line.find(needle, start)
            if start < 0:
                break
            member_start = start + len(needle)
            member_end = member_start
            while member_end < len(line) and (
                line[member_end].isalnum() or line[member_end] == "_"
            ):
                member_end += 1
            if member_end == member_start:
                start += len(needle)
                continue
            if start <= position.character <= member_end:
                full_name = line[start:member_end]
                return ResolvedSymbol(
                    ctx.uri,
                    full_name,
                    full_name,
                    "module_member",
                    make_range(position.line, start, member_end),
                )
            start = member_end
    return None


def resolve_dotted_word(ctx, word: str, word_range) -> ResolvedSymbol | None:
    if "." not in word:
        return None
    root, _sep, _rest = word.partition(".")
    imported_modules = {symbol.name for symbol in ctx.symbols() if symbol.kind == "import"}
    if root not in imported_modules:
        return None
    return ResolvedSymbol(ctx.uri, word, word, "module_member", word_range)
