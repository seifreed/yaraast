"""Coverage for symbol-tree text fallback (sections and string children)."""

from __future__ import annotations

from typing import Any, cast

from yaraast.lsp.symbols import SymbolsProvider

UNPARSEABLE_RICH = (
    'import "pe"\n'
    'include "./other.yar"\n'
    "rule broken {\n"
    "    meta:\n"
    '        author = "alice"\n'
    "    strings:\n"
    '        $s1 = "x"\n'
    '        $s2 = "y"\n'
    "    condition:\n"
)


def test_text_fallback_builds_sections_and_string_children() -> None:
    symbols = SymbolsProvider().get_symbols(UNPARSEABLE_RICH)
    names = [s.name for s in symbols]
    assert 'import "pe"' in names
    assert "broken" in names

    rule = next(s for s in symbols if s.name == "broken")
    child_names = [c.name for c in cast(list[Any], rule.children or [])]
    assert {"meta", "strings", "condition"} <= set(child_names)

    strings_section = next(c for c in cast(list[Any], rule.children or []) if c.name == "strings")
    string_ids = {c.name for c in cast(list[Any], strings_section.children or [])}
    assert "$s1" in string_ids and "$s2" in string_ids
