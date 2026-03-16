from __future__ import annotations

from yaraast.yaral import generator_helpers as gh


class _Visitable:
    def accept(self, visitor):
        return "x"


def test_format_literal_returns_empty_for_visitable_nodes() -> None:
    assert gh.format_literal(_Visitable()) == ""


def test_format_udm_path_handles_empty_and_bracket_parts() -> None:
    assert gh.format_udm_path([]) == ""
    assert gh.format_udm_path(["principal", "[0]", "ip"]) == "principal[0].ip"
