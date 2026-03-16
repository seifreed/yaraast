"""Extra tests for code actions (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.lsp.code_actions import CodeActionsProvider


def _range(line: int, start: int, end: int) -> Range:
    return Range(start=Position(line=line, character=start), end=Position(line=line, character=end))


def test_code_actions_no_condition_refactor() -> None:
    text = """
rule r {
    strings:
        $a = "abc"
    condition:
        $a
}
""".lstrip()

    provider = CodeActionsProvider()
    actions = provider.get_code_actions(text, _range(1, 4, 6), [], "file://test.yar")
    assert not any(a.title == "Extract to rule" for a in actions)
