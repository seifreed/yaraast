"""Coverage for YARA-L match-section parsing (grouping fields, paths, windows)."""

from __future__ import annotations

import pytest

from yaraast.yaral.parser import YaraLParser

_EVENTS = '  events:\n    $e.metadata.event_type = "A"\n'
_EVENTS2 = "  events:\n" '    $e1.metadata.event_type = "A"\n' '    $e2.metadata.event_type = "B"\n'


@pytest.mark.parametrize(
    "match_line",
    [
        "    $e = principal.ip over 5m",
        '    $e = udm["key"] over 5m',
        "    $e = list[0] over 1h",
        "    $e over every 1h",
    ],
)
def test_match_section_variants_parse(match_line: str) -> None:
    source = f"rule r {{\n{_EVENTS}  match:\n{match_line}\n  condition:\n    $e\n}}"
    assert YaraLParser(source).parse().rules


def test_match_multiple_variables_without_grouping() -> None:
    source = (
        "rule r {\n"
        f"{_EVENTS2}"
        "  match:\n"
        "    $e1, $e2 over 5m\n"
        "  condition:\n"
        "    $e1 and $e2\n"
        "}"
    )
    assert YaraLParser(source).parse().rules


def test_match_grouping_field_rejects_multiple_variables() -> None:
    source = (
        "rule r {\n"
        f"{_EVENTS2}"
        "  match:\n"
        "    $e1, $e2 = principal.ip over 5m\n"
        "  condition:\n"
        "    $e1 and $e2\n"
        "}"
    )
    with pytest.raises(Exception, match="single match variable"):
        YaraLParser(source).parse()
