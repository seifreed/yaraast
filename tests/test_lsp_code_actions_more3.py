"""More tests for LSP code actions (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Diagnostic, Position, Range

from yaraast.lsp.code_actions import CodeActionsProvider


def _range(line: int, start: int, end: int) -> Range:
    return Range(start=Position(line=line, character=start), end=Position(line=line, character=end))


def test_code_action_add_string_definition() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $payload
}
""".lstrip()

    provider = CodeActionsProvider()
    diagnostics = [
        Diagnostic(
            range=_range(4, 4, 12),
            message="Undefined variable $payload",
        )
    ]
    actions = provider.get_code_actions(text, _range(4, 4, 12), diagnostics, "file://test.yar")
    assert any("Add string definition" in action.title for action in actions)


def test_code_action_add_import_module() -> None:
    text = "rule a { condition: pe.entry_point == 0 }"
    provider = CodeActionsProvider()
    diagnostics = [
        Diagnostic(
            range=_range(0, 0, 4),
            message="Module 'pe' not imported",
        )
    ]
    actions = provider.get_code_actions(text, _range(0, 0, 4), diagnostics, "file://test.yar")
    assert any(action.title == 'Add import "pe"' for action in actions)
    assert actions[0].edit is not None


def test_code_action_rename_duplicate() -> None:
    text = """
rule a {
  strings:
    $a = "x"
    $a = "y"
  condition:
    $a
}
""".lstrip()

    provider = CodeActionsProvider()
    diagnostics = [
        Diagnostic(
            range=_range(3, 4, 6),
            message="Duplicate string identifier '$a'",
        )
    ]
    actions = provider.get_code_actions(text, _range(3, 4, 6), diagnostics, "file://test.yar")
    assert any("Rename to $a_" in action.title for action in actions)


def test_refactor_action_in_condition() -> None:
    text = """
rule a {
  condition:
    true
}
""".lstrip()
    provider = CodeActionsProvider()
    actions = provider.get_code_actions(text, _range(2, 4, 8), [], "file://test.yar")
    assert any(action.title == "Extract to rule" for action in actions)
