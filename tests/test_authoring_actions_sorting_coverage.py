"""Coverage for LSP authoring sorting/canonicalization code actions."""

from __future__ import annotations

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.authoring import AuthoringActions

UNSORTED_RULE = (
    "rule r : zebra alpha {\n"
    "    meta:\n"
    "        zebra = 1\n"
    "        alpha = 2\n"
    "    strings:\n"
    '        $z = "z"\n'
    '        $a = "a"\n'
    "    condition:\n"
    "        $a and $z\n"
    "}\n"
)

_FULL_SELECTION = Range(start=Position(line=0, character=0), end=Position(line=9, character=0))


@pytest.mark.parametrize(
    "action",
    [
        "sort_strings_by_identifier",
        "sort_meta_by_key",
        "sort_tags_alphabetically",
        "canonicalize_rule_structure",
        "pretty_print_rule",
    ],
)
def test_authoring_sorting_actions_produce_edits(action: str) -> None:
    authoring = AuthoringActions()
    edit = getattr(authoring, action)(UNSORTED_RULE, _FULL_SELECTION)
    assert edit is not None


def test_authoring_sorting_actions_handle_unparseable_text() -> None:
    authoring = AuthoringActions()
    broken = 'rule broken {\n  strings:\n    $a = "x"\n  condition:\n'
    # Unparseable input must not raise; it returns None or an edit.
    assert authoring.sort_strings_by_identifier(broken, _FULL_SELECTION) is None
