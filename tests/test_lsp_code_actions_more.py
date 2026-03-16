"""Real tests for LSP code actions (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Diagnostic, Position, Range

from yaraast.lsp.code_actions import CodeActionsProvider


def _range(line: int, start: int, end: int) -> Range:
    return Range(start=Position(line=line, character=start), end=Position(line=line, character=end))


def test_code_actions_add_string_import_and_rename() -> None:
    text = """
rule r {
    strings:
        $a = "abc"
    condition:
        $missing
}
""".lstrip()
    provider = CodeActionsProvider()
    uri = "file://test.yar"

    diagnostics = [
        Diagnostic(
            range=_range(4, 8, 16),
            message="undefined variable $missing",
        ),
        Diagnostic(
            range=_range(0, 0, 1),
            message="Module 'pe' not imported",
        ),
        Diagnostic(
            range=_range(2, 8, 10),
            message="Duplicate string identifier '$a' in rule 'r'",
        ),
    ]

    actions = provider.get_code_actions(text, _range(4, 0, 10), diagnostics, uri)
    titles = [a.title for a in actions]

    assert any("Add string definition" in t for t in titles)
    assert any("Add import" in t for t in titles)
    assert any("Rename to" in t for t in titles)


def test_code_actions_refactor_extract() -> None:
    text = """
rule r {
    condition:
        true
}
""".lstrip()
    provider = CodeActionsProvider()
    uri = "file://test.yar"

    actions = provider.get_code_actions(text, _range(2, 4, 8), [], uri)
    assert any(a.title == "Extract to rule" for a in actions)
