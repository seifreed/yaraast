"""Coverage for LSP completion context detection and completion builders."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

from lsprotocol.types import Position
import pytest

from yaraast.lsp.completion import CompletionProvider
from yaraast.lsp.completion_helpers import (
    _active_module_name,
    analyze_context,
    build_module_member_completions,
)
from yaraast.types.module_loader import ModuleLoader


def _ctx(text: str, line: int, character: int) -> str:
    return analyze_context(text, Position(line=line, character=character))


@pytest.mark.parametrize(
    ("text", "line", "character", "expected"),
    [
        ('$a = "x" nocase', 0, 15, "string_modifier"),
        ('$a = "', 0, 6, "string_modifier"),
        ('import "', 0, 8, "import"),
        ("condition: pe.", 0, 14, "module_member"),
        ("rule r {\ncondition:\nx", 2, 1, "condition"),
        ("rule r {\nmeta:\nx", 2, 1, "meta"),
        ("rule r {\nstrings:\nx", 2, 1, "strings"),
        ("rule r {", 5, 0, "general"),
    ],
)
def test_analyze_context_classifies_position(
    text: str, line: int, character: int, expected: str
) -> None:
    assert _ctx(text, line, character) == expected


@pytest.mark.parametrize(
    ("before_cursor", "expected"),
    [
        ("pe.imports", "pe"),
        ("foo", None),
        ("1bad.x", None),
        ("pe.1bad", None),
        ("pe.imports x", None),
    ],
)
def test_active_module_name(before_cursor: str, expected: str | None) -> None:
    assert _active_module_name(before_cursor) == expected


def _completion_count(text: str, line: int, character: int) -> int:
    result = CompletionProvider().get_completions(text, Position(line=line, character=character))
    items = cast(Sequence[Any], getattr(result, "items", result))
    return len(items)


def test_module_member_completions() -> None:
    assert _completion_count('import "pe"\nrule r {\n condition: pe.\n}', 2, 15) > 0


def test_string_identifier_completions() -> None:
    text = 'rule r {\n strings:\n  $abc = "x"\n condition:\n  $\n}'
    assert _completion_count(text, 4, 3) > 0


def test_loop_variable_completions() -> None:
    text = 'rule r {\n strings:\n  $a = "x"\n condition:\n  for any i in (1..3) : ( i\n}'
    assert _completion_count(text, 4, 27) > 0


@pytest.mark.parametrize(
    "access_chain",
    [
        "",  # top-level members, exercises array/struct/dict field detail branches
        "rich_signature",  # struct -> resolved field completions
        "sections[0]",  # array index -> element struct fields
        "linker_version.major",  # nested struct field
        "nonexistent_xyz",  # unresolved chain falls back to member listing
    ],
)
def test_build_module_member_completions_access_chains(access_chain: str) -> None:
    pe_def = ModuleLoader().get_module("pe")
    assert pe_def is not None
    items = build_module_member_completions("pe", pe_def, access_chain=access_chain)
    assert isinstance(items, list)
