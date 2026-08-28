"""Lossless source refactors over lexer token ranges."""

from __future__ import annotations

from dataclasses import dataclass
import difflib
import os
from pathlib import Path
import re
import tempfile
from typing import cast

from yaraast.analysis.best_practices import BestPracticesAnalyzer
from yaraast.api import (
    DialectName,
    OutputDialectName,
    SourceEdit,
    generate,
    parse,
    rewrite_lossless,
)
from yaraast.lexer.lexer import Lexer
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser.source import parse_yara_source


@dataclass(frozen=True)
class RefactorResult:
    """Original and rewritten source for a refactor preview."""

    original: str
    updated: str
    edits: tuple[SourceEdit, ...]

    @property
    def changed(self) -> bool:
        return self.original != self.updated

    def diff(self, path: str = "rule.yar") -> str:
        """Return a unified diff for the proposed source."""
        return "".join(
            difflib.unified_diff(
                self.original.splitlines(keepends=True),
                self.updated.splitlines(keepends=True),
                fromfile=path,
                tofile=path,
            )
        )


def rename_rule(source: str, old_name: str, new_name: str) -> RefactorResult:
    """Rename identifier tokens matching a rule name and reparse the result."""
    _validate_identifier(old_name, "old rule name")
    _validate_identifier(new_name, "new rule name")
    return _rewrite_tokens(source, TokenType.IDENTIFIER, old_name, new_name)


def rename_string(source: str, old_name: str, new_name: str) -> RefactorResult:
    """Rename all tokenized references to one string identifier."""
    old = _string_name(old_name)
    new = _string_name(new_name)
    result = _rewrite_tokens(source, TokenType.STRING_IDENTIFIER, old, new)
    if not result.changed:
        raise ValueError(f"string identifier not found: {old}")
    return result


def remove_unused_strings(source: str) -> RefactorResult:
    """Remove unused one-definition-per-line strings from valid YARA source."""
    ast = parse_yara_source(source)
    unused: dict[str, set[str]] = {}
    for suggestion in BestPracticesAnalyzer().analyze(ast).suggestions:
        match = re.fullmatch(
            r"String '(\$[A-Za-z_][A-Za-z0-9_]*)' is defined but never used in condition",
            suggestion.message,
        )
        if match:
            unused.setdefault(suggestion.rule_name, set()).add(match.group(1))

    edits: list[SourceEdit] = []
    current_rule: str | None = None
    rule_pattern = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    string_pattern = re.compile(r"^(\s*)(\$[A-Za-z_][A-Za-z0-9_]*)\s*=.*(?:\r?\n|$)")
    for start, line in _line_starts(source):
        rule_match = rule_pattern.match(line)
        if rule_match:
            current_rule = rule_match.group(1)
        string_match = string_pattern.match(line)
        if string_match and string_match.group(2) in unused.get(current_rule or "", set()):
            edits.append(_line_edit(source, start, line, ""))
    return _result_from_edits(source, edits)


def normalize_metadata(source: str) -> RefactorResult:
    """Sort simple metadata entries within each metadata section."""
    parse_yara_source(source)
    edits: list[SourceEdit] = []
    lines = list(_line_starts(source))
    index = 0
    while index < len(lines):
        _, line = lines[index]
        if line.strip() != "meta:":
            index += 1
            continue
        block_start = index + 1
        block_end = block_start
        while block_end < len(lines):
            section = lines[block_end][1].strip()
            if section.startswith(("strings:", "condition:")) or section == "}":
                break
            block_end += 1
        entries: list[tuple[int, str, re.Match[str]]] = []
        for position, (_, value) in enumerate(lines[block_start:block_end], block_start):
            if not value.strip():
                continue
            match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", value)
            if match is None:
                entries = []
                break
            entries.append((position, value, match))
        if entries:
            ordered = sorted(entries, key=lambda item: item[2].group(1))
            for (position, _, _), (_, replacement, _) in zip(entries, ordered, strict=True):
                if lines[position][1] != replacement:
                    edits.append(
                        _line_edit(source, lines[position][0], lines[position][1], replacement)
                    )
        index = block_end
    return _result_from_edits(source, edits)


def sort_imports(source: str) -> RefactorResult:
    """Sort contiguous top-level import statements by module text."""
    parse_yara_source(source)
    lines = list(_line_starts(source))
    import_pattern = re.compile(
        r"^(\s*import\s+\"[^\"]+\"(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\r?\n|$))$"
    )
    import_positions = [
        index for index, (_, line) in enumerate(lines) if import_pattern.fullmatch(line)
    ]
    edits: list[SourceEdit] = []
    for group in _contiguous_groups(import_positions):
        original = [lines[index][1] for index in group]
        ordered = sorted(original, key=lambda value: value.strip())
        for index, replacement in zip(group, ordered, strict=True):
            if lines[index][1] != replacement:
                edits.append(_line_edit(source, lines[index][0], lines[index][1], replacement))
    return _result_from_edits(source, edits)


def migrate_source(source: str, from_dialect: str, to_dialect: str) -> RefactorResult:
    """Convert valid YARA-family source between supported output dialects."""
    document = parse(source, dialect=cast(DialectName, from_dialect))
    updated = generate(document, dialect=cast(OutputDialectName, to_dialect))
    parse(updated, dialect=cast(DialectName, to_dialect))
    return RefactorResult(source, updated, ())


def write_refactor(path: str | Path, result: RefactorResult) -> None:
    """Atomically write a validated refactor result."""
    target = Path(path)
    if target.is_symlink():
        raise ValueError("refactor target must not be a symlink")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=target.parent, prefix=f".{target.name}.", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(result.updated)
    try:
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _rewrite_tokens(
    source: str,
    token_type: TokenType,
    old_name: str,
    new_name: str,
) -> RefactorResult:
    parse_yara_source(source)
    lines = source.splitlines(keepends=True)
    offsets: list[int] = []
    current = 0
    for line in lines:
        offsets.append(current)
        current += len(line)
    edits = []
    tokens = cast(list[Token], Lexer(source).tokenize())
    for token in tokens:
        if token.type is not token_type or token.value != old_name:
            continue
        char_start = offsets[token.line - 1] + token.column - 1
        char_end = char_start + len(old_name)
        start = len(source[:char_start].encode("utf-8"))
        end = len(source[:char_end].encode("utf-8"))
        edits.append(SourceEdit(start, end, new_name))
    return _result_from_edits(source, edits)


def _result_from_edits(source: str, edits: list[SourceEdit]) -> RefactorResult:
    updated = rewrite_lossless(source, edits)
    parse_yara_source(updated)
    return RefactorResult(source, updated, tuple(edits))


def _line_starts(source: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    offset = 0
    for line in source.splitlines(keepends=True):
        lines.append((offset, line))
        offset += len(line)
    if not lines or offset < len(source):
        lines.append((offset, source[offset:]))
    return lines


def _line_edit(source: str, start: int, line: str, replacement: str) -> SourceEdit:
    end = start + len(line)
    return SourceEdit(
        len(source[:start].encode("utf-8")),
        len(source[:end].encode("utf-8")),
        replacement,
    )


def _contiguous_groups(positions: list[int]) -> list[list[int]]:
    groups: list[list[int]] = []
    for position in positions:
        if not groups or position != groups[-1][-1] + 1:
            groups.append([position])
        else:
            groups[-1].append(position)
    return groups


def _validate_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
        raise ValueError(f"{field_name} must be a valid YARA identifier")


def _string_name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("string identifier must be a string")
    normalized = value if value.startswith("$") else f"${value}"
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", normalized) is None:
        raise ValueError("string identifier must be a valid YARA string identifier")
    return normalized
