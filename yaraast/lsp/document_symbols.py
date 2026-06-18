"""Symbol extraction and indexing for LSP document contexts."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from lsprotocol.types import Position, Range

from yaraast.lsp.document_symbol_ranges import (
    node_range,
    node_value_range,
    quoted_value_range_from_node_line,
)
from yaraast.lsp.document_symbol_sections import (
    append_condition_symbols,
    append_extra_section_symbols,
    append_meta_symbols,
    append_string_symbols,
)
from yaraast.lsp.document_types import SymbolRecord
from yaraast.lsp.structure import (
    find_line_containing,
    find_quoted_value_range,
    find_rule_end,
    find_rule_line,
    make_range,
)
from yaraast.lsp.utf16 import utf8_col_to_utf16

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext

IMPORT_DIRECTIVE_RE = re.compile(r'^\s*import\s+"(?P<value>(?:\\.|[^"\\])*)"')
INCLUDE_DIRECTIVE_RE = re.compile(r'^\s*include\s+"(?P<value>(?:\\.|[^"\\])*)"')
RULE_DECLARATION_RE = re.compile(
    r"^\s*(?:(?:global|private)\s+)*rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)


def build_symbols(ctx: DocumentContext, ast: Any, lines: list[str]) -> list[SymbolRecord]:
    symbols: list[SymbolRecord] = []

    _build_import_symbols(ctx, ast, lines, symbols)
    _build_include_symbols(ctx, ast, lines, symbols)

    for rule in ctx._iter_rules(ast):
        _build_rule_symbol(ctx, rule, lines, symbols)

    return symbols


def build_text_symbols(ctx: DocumentContext, lines: list[str]) -> list[SymbolRecord]:
    symbols: list[SymbolRecord] = []
    _build_text_import_symbols(ctx, lines, symbols)
    _build_text_include_symbols(ctx, lines, symbols)
    _build_text_rule_symbols(ctx, lines, symbols)
    return symbols


def _build_text_import_symbols(
    ctx: DocumentContext, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    for line_num, line in enumerate(lines):
        match = IMPORT_DIRECTIVE_RE.match(line)
        if match is None:
            continue
        symbol_range = _quoted_text_range(line, line_num, match.group("value"))
        if symbol_range is not None:
            symbols.append(
                SymbolRecord(
                    name=match.group("value"),
                    kind="import",
                    uri=ctx.uri,
                    range=symbol_range,
                )
            )


def _build_text_include_symbols(
    ctx: DocumentContext, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    for line_num, line in enumerate(lines):
        match = INCLUDE_DIRECTIVE_RE.match(line)
        if match is None:
            continue
        symbol_range = _quoted_text_range(line, line_num, match.group("value"))
        if symbol_range is not None:
            symbols.append(
                SymbolRecord(
                    name=match.group("value"),
                    kind="include",
                    uri=ctx.uri,
                    range=symbol_range,
                )
            )


def _build_text_rule_symbols(
    ctx: DocumentContext, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    seen: set[str] = set()
    for line_num, line in enumerate(lines):
        match = RULE_DECLARATION_RE.match(line)
        if match is None:
            continue
        rule_name = match.group("name")
        if rule_name in seen:
            continue
        seen.add(rule_name)
        rule_line = line_num
        rule_end = find_rule_end(lines, rule_line)
        rule_name_col = line.find(rule_name, match.start("name"), match.end("name"))
        if rule_name_col < 0:
            continue
        name_range = make_range(
            rule_line,
            utf8_col_to_utf16(line, rule_name_col),
            utf8_col_to_utf16(line, rule_name_col + len(rule_name)),
        )
        block_range = Range(
            start=Position(line=rule_line, character=0),
            end=Position(
                line=rule_end,
                character=utf8_col_to_utf16(lines[rule_end], len(lines[rule_end])),
            ),
        )
        symbols.append(SymbolRecord(name=rule_name, kind="rule", uri=ctx.uri, range=name_range))
        symbols.append(
            SymbolRecord(name=rule_name, kind="rule_block", uri=ctx.uri, range=block_range)
        )


def _quoted_text_range(line: str, line_num: int, value: str) -> Range | None:
    quoted = f'"{value}"'
    start = line.find(quoted)
    if start < 0:
        start = line.find(value)
    if start < 0:
        return None
    value_start = start + 1 if start < len(line) and line[start] == '"' else start
    end = value_start + len(value)
    return Range(
        start=Position(line=line_num, character=utf8_col_to_utf16(line, value_start)),
        end=Position(line=line_num, character=utf8_col_to_utf16(line, end)),
    )


def _build_import_symbols(
    ctx: DocumentContext, ast: Any, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    """Build symbols for import statements."""
    source_text = ctx.text
    for imp in getattr(ast, "imports", []):
        symbol_range = quoted_value_range_from_node_line(lines, imp, imp.module)
        if symbol_range is None:
            symbol_range = node_value_range(imp, source_text, imp.module)
        if symbol_range is None:
            target = f'import "{imp.module}"'
            line_num = find_line_containing(lines, target)
            if line_num >= 0:
                symbol_range = find_quoted_value_range(lines, line_num, imp.module)
                if symbol_range is None:
                    symbol_range = make_range(line_num, 0, len(lines[line_num]))
        if symbol_range is not None:
            symbols.append(
                SymbolRecord(
                    name=imp.module,
                    kind="import",
                    uri=ctx.uri,
                    range=symbol_range,
                )
            )


def _build_include_symbols(
    ctx: DocumentContext, ast: Any, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    """Build symbols for include statements."""
    source_text = ctx.text
    for inc in getattr(ast, "includes", []):
        include_path = getattr(inc, "path", "")
        symbol_range = quoted_value_range_from_node_line(lines, inc, include_path)
        if symbol_range is None:
            symbol_range = node_value_range(inc, source_text, include_path)
        if symbol_range is None:
            target = f'include "{include_path}"'
            line_num = find_line_containing(lines, target)
            if line_num >= 0:
                symbol_range = find_quoted_value_range(lines, line_num, include_path)
                if symbol_range is None:
                    symbol_range = make_range(line_num, 0, len(lines[line_num]))
        if symbol_range is not None:
            symbols.append(
                SymbolRecord(
                    name=include_path,
                    kind="include",
                    uri=ctx.uri,
                    range=symbol_range,
                )
            )


def _build_rule_symbol(
    ctx: DocumentContext, rule: Any, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    """Build DocumentSymbol entries for a single rule."""
    source_text = ctx.text
    rule_name = getattr(rule, "name", None)
    if not rule_name:
        return
    rule_block_range = node_range(rule, source_text)
    rule_name_range = node_value_range(rule, source_text, rule_name)
    if rule_block_range is None or rule_name_range is None:
        rule_line = find_rule_line(lines, rule_name)
        if rule_line < 0:
            return
        rule_end = find_rule_end(lines, rule_line)
        rule_name_col = lines[rule_line].find(rule_name)
        rule_name_range = make_range(rule_line, rule_name_col, rule_name_col + len(rule_name))
        rule_block_range = Range(
            start=Position(line=rule_line, character=0),
            end=Position(line=rule_end, character=len(lines[rule_end])),
        )
    symbols.append(
        SymbolRecord(
            name=rule_name,
            kind="rule",
            uri=ctx.uri,
            range=rule_name_range,
        )
    )
    symbols.append(
        SymbolRecord(
            name=rule_name,
            kind="rule_block",
            uri=ctx.uri,
            range=rule_block_range,
        )
    )

    append_meta_symbols(ctx, symbols, lines, rule, rule_name, rule_block_range)
    append_string_symbols(ctx, symbols, lines, rule, rule_name, rule_block_range, source_text)
    append_condition_symbols(ctx, symbols, lines, rule, rule_name, rule_block_range, source_text)
    append_extra_section_symbols(
        ctx, symbols, lines, rule, rule_name, rule_block_range, source_text
    )


def build_symbol_indexes(
    symbols: list[SymbolRecord],
) -> tuple[dict[str, list[SymbolRecord]], dict[tuple[str, str, str | None], SymbolRecord]]:
    by_kind: dict[str, list[SymbolRecord]] = {}
    lookup: dict[tuple[str, str, str | None], SymbolRecord] = {}
    for symbol in symbols:
        by_kind.setdefault(symbol.kind, []).append(symbol)
        lookup[symbol.kind, symbol.name, symbol.container_name] = symbol
    return by_kind, lookup
