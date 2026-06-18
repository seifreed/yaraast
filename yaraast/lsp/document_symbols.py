"""Symbol extraction and indexing for LSP document contexts."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Any

from lsprotocol.types import Position, Range

from yaraast.lsp.document_query_resolution_text import position_is_in_non_code_segment
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
    find_section_header_position,
    find_section_header_range,
    find_section_range,
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
STRING_DECLARATION_RE = re.compile(r"^\s*(?P<identifier>\$[A-Za-z_][A-Za-z0-9_]*)\s*=")


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
    _build_text_section_symbols(ctx, lines, symbols)
    _build_text_meta_symbols(ctx, lines, symbols)
    _build_text_string_symbols(ctx, lines, symbols)
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


def _build_text_section_symbols(
    ctx: DocumentContext, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    section_names = ("meta", "strings", "condition", "events", "match", "outcome", "options")
    seen: set[tuple[str, str]] = set()
    for rule_name, rule_line, rule_end in _iter_text_rules(lines):
        for section_name in section_names:
            position = find_section_header_position(lines, section_name, rule_line, rule_end)
            if position is None:
                continue
            line_num, column = position
            key = (rule_name, section_name)
            if key in seen:
                continue
            seen.add(key)
            section_header_range = find_section_header_range(lines, section_name, line_num, column)
            section_range = find_section_range(lines, section_name, rule_line, rule_end)
            if section_range is None:
                section_range = make_range(line_num, 0, len(lines[line_num]))
            symbols.append(
                SymbolRecord(
                    name=section_name,
                    kind="section",
                    uri=ctx.uri,
                    range=section_range,
                    container_name=rule_name,
                )
            )
            symbols.append(
                SymbolRecord(
                    name=section_name,
                    kind="section_header",
                    uri=ctx.uri,
                    range=section_header_range,
                    container_name=rule_name,
                )
            )


def _build_text_meta_symbols(
    ctx: DocumentContext, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    seen: set[tuple[str, str, str]] = set()
    section_names = ("meta", "strings", "condition", "events", "match", "outcome", "options")
    for rule_name, rule_line, rule_end in _iter_text_rules(lines):
        meta_position = find_section_header_position(lines, "meta", rule_line, rule_end)
        if meta_position is None:
            continue
        meta_line = meta_position[0]
        stop_line = rule_end
        for section_name in section_names:
            if section_name == "meta":
                continue
            section_position = find_section_header_position(
                lines, section_name, meta_line + 1, rule_end
            )
            if section_position is None:
                continue
            stop_line = min(stop_line, section_position[0] - 1)
        for line_num in range(meta_line + 1, stop_line + 1):
            line = lines[line_num]
            stripped = line.strip()
            if not stripped:
                continue
            if not line.startswith((" ", "\t")):
                break
            if "=" not in stripped:
                continue
            key_text, raw_value = stripped.split("=", 1)
            key = key_text.strip()
            if not key:
                continue
            value = _parse_text_meta_value(raw_value.strip())
            if value is None and raw_value.strip().lower() not in {"null", "none"}:
                value = raw_value.strip().strip('"')
            dedupe_key = (rule_name, key, str(value))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            key_start = line.find(key)
            if key_start < 0:
                continue
            symbols.append(
                SymbolRecord(
                    name=key,
                    kind="meta",
                    uri=ctx.uri,
                    range=make_range(
                        line_num,
                        utf8_col_to_utf16(line, key_start),
                        utf8_col_to_utf16(line, key_start + len(key)),
                    ),
                    container_name=rule_name,
                )
            )


def _build_text_string_symbols(
    ctx: DocumentContext, lines: list[str], symbols: list[SymbolRecord]
) -> None:
    seen: set[tuple[str, str | None]] = set()
    for rule_name, rule_line, rule_end in _iter_text_rules(lines):
        section_position = find_section_header_position(lines, "strings", rule_line, rule_end)
        if section_position is None:
            continue
        section_line = section_position[0]
        section_range = find_section_range(lines, "strings", rule_line, rule_end)
        stop_line = rule_end if section_range is None else section_range.end.line
        for line_num in range(section_line + 1, stop_line + 1):
            line = lines[line_num]
            match = STRING_DECLARATION_RE.match(line)
            if match is None:
                continue
            identifier = match.group("identifier")
            key = (identifier, rule_name)
            if key in seen:
                continue
            start_col = match.start("identifier")
            position = Position(
                line=line_num,
                character=utf8_col_to_utf16(line, start_col),
            )
            if position_is_in_non_code_segment(ctx, position):
                continue
            seen.add(key)
            end_col = match.end("identifier")
            symbols.append(
                SymbolRecord(
                    name=identifier,
                    kind="string",
                    uri=ctx.uri,
                    range=Range(
                        start=Position(
                            line=line_num,
                            character=utf8_col_to_utf16(line, start_col),
                        ),
                        end=Position(
                            line=line_num,
                            character=utf8_col_to_utf16(line, end_col),
                        ),
                    ),
                    container_name=rule_name,
                )
            )


def _iter_text_rules(lines: list[str]) -> list[tuple[str, int, int]]:
    rules: list[tuple[str, int, int]] = []
    for line_num, line in enumerate(lines):
        match = RULE_DECLARATION_RE.match(line)
        if match is None:
            continue
        rule_name = match.group("name")
        rule_end = find_rule_end(lines, line_num)
        rules.append((rule_name, line_num, rule_end))
    return rules


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


def _parse_text_meta_value(raw_value: str) -> Any | None:
    try:
        return ast.literal_eval(raw_value)
    except (SyntaxError, ValueError):
        lowered = raw_value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered in {"null", "none"}:
            return None
    return None


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
