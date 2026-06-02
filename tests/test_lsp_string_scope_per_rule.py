"""Regression tests: string identifiers are scoped to their containing rule.

A ``$foo`` string in one rule is a distinct symbol from a ``$foo`` string in
another rule. Find-references, go-to-definition, rename, and document highlight
must operate only within the rule that contains the cursor and must never leak
across rule boundaries.
"""

from __future__ import annotations

from lsprotocol.types import Location, Position

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.document_highlight import DocumentHighlightProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider

_TEXT = """rule A
{
    strings:
        $foo = "aaa"
    condition:
        $foo
}

rule B
{
    strings:
        $foo = "bbb"
    condition:
        $foo
}
"""

_URI = "file://scope.yar"

# Line indices: rule A def=3, use=5 ; rule B def=11, use=13.
_RULE_B_USE = Position(line=13, character=9)
_RULE_A_USE = Position(line=5, character=9)


def test_references_scoped_to_rule_b() -> None:
    refs = ReferencesProvider().get_references(_TEXT, _RULE_B_USE, _URI)
    lines = sorted(ref.range.start.line for ref in refs)
    assert lines == [11, 13]


def test_references_scoped_to_rule_a() -> None:
    refs = ReferencesProvider().get_references(_TEXT, _RULE_A_USE, _URI)
    lines = sorted(ref.range.start.line for ref in refs)
    assert lines == [3, 5]


def test_definition_resolves_to_own_rule() -> None:
    loc = DefinitionProvider().get_definition(_TEXT, _RULE_B_USE, _URI)
    assert isinstance(loc, Location)
    assert loc.range.start.line == 11


def test_rename_only_touches_own_rule() -> None:
    edit = RenameProvider().rename(_TEXT, _RULE_B_USE, "bar", _URI)
    assert edit is not None and edit.changes is not None
    edited_lines = sorted(
        change.range.start.line for changes in edit.changes.values() for change in changes
    )
    assert edited_lines == [11, 13]


def test_highlight_scoped_to_rule_b() -> None:
    highlights = DocumentHighlightProvider().get_highlights(_TEXT, _RULE_B_USE)
    lines = sorted(highlight.range.start.line for highlight in highlights)
    assert lines == [11, 13]
