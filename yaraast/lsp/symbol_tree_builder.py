"""Builders for LSP document symbol trees."""

from __future__ import annotations

from typing import Any, cast

from lsprotocol.types import DocumentSymbol, Position, Range, SymbolKind


def build_document_symbols(doc, lines: list[str]) -> list[DocumentSymbol]:
    symbols: list[DocumentSymbol] = []
    _append_import_symbols(symbols, doc, lines)
    _append_include_symbols(symbols, doc, lines)

    for rule_name in doc.get_rule_names():
        rule = doc.get_rule(rule_name)
        if rule is None:
            continue
        rule_symbol = _build_rule_symbol(doc, lines, rule, rule_name)
        if rule_symbol is not None:
            symbols.append(rule_symbol)
    return symbols


def _append_import_symbols(symbols: list[DocumentSymbol], doc, lines: list[str]) -> None:
    for module_name in doc.get_import_modules():
        record = doc.find_symbol_record("import", module_name)
        if record is not None:
            symbols.append(
                DocumentSymbol(
                    name=f'import "{record.name}"',
                    kind=SymbolKind.Namespace,
                    range=record.range,
                    selection_range=record.range,
                )
            )
            continue
        line_num = find_line_containing(lines, f'import "{module_name}"')
        if line_num >= 0:
            line_range = make_range(line_num, 0, line_num, len(lines[line_num]))
            symbols.append(
                DocumentSymbol(
                    name=f'import "{module_name}"',
                    kind=SymbolKind.Namespace,
                    range=line_range,
                    selection_range=line_range,
                )
            )


def _append_include_symbols(symbols: list[DocumentSymbol], doc, lines: list[str]) -> None:
    for include_path in doc.get_include_paths():
        record = doc.find_symbol_record("include", include_path)
        if record is not None:
            symbols.append(
                DocumentSymbol(
                    name=f'include "{record.name}"',
                    kind=SymbolKind.File,
                    range=record.range,
                    selection_range=record.range,
                )
            )
            continue
        line_num = find_line_containing(lines, f'include "{include_path}"')
        if line_num >= 0:
            line_range = make_range(line_num, 0, line_num, len(lines[line_num]))
            symbols.append(
                DocumentSymbol(
                    name=f'include "{include_path}"',
                    kind=SymbolKind.File,
                    range=line_range,
                    selection_range=line_range,
                )
            )


def _build_rule_symbol(doc, lines: list[str], rule: Any, rule_name: str) -> DocumentSymbol | None:
    rule_record = doc.find_symbol_record("rule", rule_name)
    rule_block_record = doc.find_symbol_record("rule_block", rule_name)
    rule_line = (
        rule_record.range.start.line
        if rule_record is not None
        else find_line_containing(lines, f"rule {rule_name}")
    )
    if rule_line < 0:
        return None
    rule_end = (
        rule_block_record.range.end.line
        if rule_block_record is not None
        else find_closing_brace(lines, rule_line)
    )

    rule_symbol = DocumentSymbol(
        name=rule_name,
        kind=SymbolKind.Class,
        range=(
            rule_block_record.range
            if rule_block_record is not None
            else make_range(
                rule_line, 0, rule_end, len(lines[rule_end]) if rule_end < len(lines) else 0
            )
        ),
        selection_range=(
            rule_record.range
            if rule_record is not None
            else make_range(
                rule_line,
                lines[rule_line].index(rule.name),
                rule_line,
                lines[rule_line].index(rule.name) + len(rule.name),
            )
        ),
        children=[],
    )

    section_names = set(doc.get_rule_sections(rule_name))
    _append_meta_section(rule_symbol, doc, lines, rule, rule_name, rule_line, section_names)
    _append_strings_section(rule_symbol, doc, lines, rule, rule_name, rule_line, section_names)
    _append_condition_section(
        rule_symbol, doc, lines, rule, rule_name, rule_line, rule_end, section_names
    )
    _append_extra_sections(rule_symbol, doc, lines, rule, rule_name, rule_line, section_names)
    return rule_symbol


def _append_meta_section(
    rule_symbol: DocumentSymbol,
    doc,
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_line: int,
    section_names: set[str],
) -> None:
    if "meta" not in section_names and not rule.meta:
        return
    meta_section_record = doc.find_symbol_record("section", "meta", rule_name)
    meta_header_record = doc.find_symbol_record("section_header", "meta", rule_name)
    meta_line = (
        meta_section_record.range.start.line
        if meta_section_record is not None
        else find_line_containing(lines, "meta:", rule_line)
    )
    if meta_line < 0:
        return
    meta_children = _build_meta_children(doc, lines, rule, rule_name, meta_line)
    if meta_children:
        rule_symbol.children.append(
            DocumentSymbol(
                name="meta",
                kind=SymbolKind.Namespace,
                range=(
                    meta_section_record.range
                    if meta_section_record is not None
                    else make_range(meta_line, 0, meta_line, len(lines[meta_line]))
                ),
                selection_range=(
                    meta_header_record.range
                    if meta_header_record is not None
                    else make_range(meta_line, 0, meta_line, len(lines[meta_line]))
                ),
                children=meta_children,
            )
        )


def _build_meta_children(
    doc, lines: list[str], rule: Any, rule_name: str, meta_line: int
) -> list[DocumentSymbol]:
    """Build DocumentSymbol children for each meta key-value pair."""
    children: list[DocumentSymbol] = []
    meta_items = doc.get_rule_meta_items(rule_name)
    if not meta_items and hasattr(rule.meta, "entries"):
        meta_items = [(entry.key, entry.value) for entry in getattr(rule.meta, "entries", [])]
    for key, value in cast(Any, meta_items):
        meta_record = doc.find_symbol_record("meta", key, rule_name)
        key_line = (
            meta_record.range.start.line
            if meta_record is not None
            else find_line_containing(lines, f"{key} =", meta_line)
        )
        key_range = (
            meta_record.range
            if meta_record is not None
            else (
                make_range(key_line, 0, key_line, len(lines[key_line])) if key_line >= 0 else None
            )
        )
        if key_line >= 0 and key_range is not None:
            children.append(
                DocumentSymbol(
                    name=f"{key} = {value}",
                    kind=SymbolKind.Property,
                    range=key_range,
                    selection_range=key_range,
                )
            )
    return children


def _append_strings_section(
    rule_symbol: DocumentSymbol,
    doc,
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_line: int,
    section_names: set[str],
) -> None:
    if "strings" not in section_names and not getattr(rule, "strings", None):
        return
    strings_section_record = doc.find_symbol_record("section", "strings", rule_name)
    strings_header_record = doc.find_symbol_record("section_header", "strings", rule_name)
    strings_line = (
        strings_section_record.range.start.line
        if strings_section_record is not None
        else find_line_containing(lines, "strings:", rule_line)
    )
    if strings_line < 0:
        return
    string_children: list[DocumentSymbol] = []
    for string_id in doc.get_rule_string_identifiers(rule_name):
        string_record = doc.find_symbol_record("string", string_id, rule_name)
        if string_record is not None:
            string_line = string_record.range.start.line
            string_range = string_record.range
        else:
            string_line = find_line_containing(lines, string_id, strings_line)
            string_range = (
                make_range(string_line, 0, string_line, len(lines[string_line]))
                if string_line >= 0
                else None
            )
        if string_line >= 0 and string_range is not None:
            string_children.append(
                DocumentSymbol(
                    name=string_id,
                    kind=SymbolKind.String,
                    range=string_range,
                    selection_range=string_range,
                )
            )
    if string_children:
        rule_symbol.children.append(
            DocumentSymbol(
                name="strings",
                kind=SymbolKind.Namespace,
                range=(
                    strings_section_record.range
                    if strings_section_record is not None
                    else make_range(strings_line, 0, strings_line, len(lines[strings_line]))
                ),
                selection_range=(
                    strings_header_record.range
                    if strings_header_record is not None
                    else make_range(strings_line, 0, strings_line, len(lines[strings_line]))
                ),
                children=string_children,
            )
        )


def _append_condition_section(
    rule_symbol: DocumentSymbol,
    doc,
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_line: int,
    rule_end: int,
    section_names: set[str],
) -> None:
    if "condition" not in section_names and not getattr(rule, "condition", None):
        return
    condition_section_record = doc.find_symbol_record("section", "condition", rule_name)
    condition_header_record = doc.find_symbol_record("section_header", "condition", rule_name)
    condition_line = (
        condition_section_record.range.start.line
        if condition_section_record is not None
        else find_line_containing(lines, "condition:", rule_line)
    )
    if condition_line < 0:
        return
    rule_symbol.children.append(
        DocumentSymbol(
            name="condition",
            kind=SymbolKind.Function,
            range=(
                condition_section_record.range
                if condition_section_record is not None
                else make_range(condition_line, 0, rule_end, len(lines[rule_end]))
            ),
            selection_range=(
                condition_header_record.range
                if condition_header_record is not None
                else make_range(condition_line, 0, condition_line, len(lines[condition_line]))
            ),
        )
    )


def _append_extra_sections(
    rule_symbol: DocumentSymbol,
    doc,
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_line: int,
    section_names: set[str],
) -> None:
    present_runtime_sections = {
        name for name in section_names if name in {"events", "match", "outcome", "options"}
    }
    for section_name, kind in [
        ("events", SymbolKind.Namespace),
        ("match", SymbolKind.Namespace),
        ("outcome", SymbolKind.Namespace),
        ("options", SymbolKind.Namespace),
    ]:
        if (
            section_name not in present_runtime_sections
            and getattr(rule, section_name, None) is None
        ):
            continue
        section_record = doc.find_symbol_record("section", section_name, rule_name)
        section_header_record = doc.find_symbol_record("section_header", section_name, rule_name)
        section_line = (
            section_record.range.start.line
            if section_record is not None
            else find_line_containing(lines, f"{section_name}:", rule_line)
        )
        if section_line >= 0:
            rule_symbol.children.append(
                DocumentSymbol(
                    name=section_name,
                    kind=kind,
                    range=(
                        section_record.range
                        if section_record is not None
                        else make_range(section_line, 0, section_line, len(lines[section_line]))
                    ),
                    selection_range=(
                        section_header_record.range
                        if section_header_record is not None
                        else make_range(section_line, 0, section_line, len(lines[section_line]))
                    ),
                )
            )


def find_line_containing(lines: list[str], text: str, start: int = 0) -> int:
    for i in range(start, len(lines)):
        if text in lines[i]:
            return i
    return -1


def _count_braces_outside_literals(line: str) -> tuple[int, int]:
    """Count { and } that are not inside string literals or comments."""
    opens = 0
    closes = 0
    in_string = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_string:
            if ch == "\\" and i + 1 < len(line):
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break  # rest of line is a comment
        elif ch == "{":
            opens += 1
        elif ch == "}":
            closes += 1
        i += 1
    return opens, closes


def find_closing_brace(lines: list[str], start: int) -> int:
    depth = 0
    for i in range(start, len(lines)):
        opens, closes = _count_braces_outside_literals(lines[i])
        depth += opens
        depth -= closes
        if depth == 0 and closes > 0:
            return i
    return len(lines) - 1


def make_range(start_line: int, start_char: int, end_line: int, end_char: int) -> Range:
    return Range(
        start=Position(line=start_line, character=start_char),
        end=Position(line=end_line, character=end_char),
    )
