"""Lossless source refactors over lexer token ranges."""

from __future__ import annotations

from dataclasses import dataclass
import difflib
import os
from pathlib import Path
import re
import tempfile
from typing import cast

from yaraast.api import SourceEdit, rewrite_lossless
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
    updated = rewrite_lossless(source, edits)
    parse_yara_source(updated)
    return RefactorResult(source, updated, tuple(edits))


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
