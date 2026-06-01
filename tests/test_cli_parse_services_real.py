"""Real integration tests for CLI parse services without test doubles."""

from __future__ import annotations

import pytest

from yaraast.cli.parse_services import parse_content_by_dialect
from yaraast.parser.parser import Parser
from yaraast.yarax.ast_nodes import WithStatement


def _yarax_code() -> str:
    return """
rule xr {
  condition:
    with xs = [1]: match xs { _ => true }
}
"""


def test_parse_services_auto_yaral() -> None:
    msgs: list[str] = []
    code = """
rule login_events {
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
}
"""
    ast, lex, par = parse_content_by_dialect(code, "auto", show_status=True, status_cb=msgs.append)
    assert ast is not None
    assert lex == []
    assert par == []
    assert any("Detected dialect: YARA_L" in m for m in msgs)


def test_parse_services_auto_yara_valid() -> None:
    code = """
rule r {
  strings:
    $a = "x"
  condition:
    $a
}
"""
    ast, lex, par = parse_content_by_dialect(code, "auto", show_status=False)
    assert ast is not None
    assert lex == []
    assert par == []


def test_parse_services_auto_yarax_preserves_extended_ast() -> None:
    msgs: list[str] = []
    ast, lex, par = parse_content_by_dialect(
        _yarax_code(), "auto", show_status=True, status_cb=msgs.append
    )
    assert isinstance(ast.rules[0].condition, WithStatement)
    assert lex == []
    assert par == []
    assert any("Detected dialect: YARA_X" in m for m in msgs)


def test_parse_services_auto_yara_invalid_fallback() -> None:
    ast, lex, par = parse_content_by_dialect("rule broken { condition:", "auto", show_status=False)
    assert ast is not None
    assert isinstance(lex, list)
    assert isinstance(par, list)


def test_parse_services_propagates_internal_parser_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_parser_parse(self: Parser, text: str | None = None) -> object:
        raise AttributeError("broken parser internals")

    monkeypatch.setattr(Parser, "parse", fail_parser_parse)

    with pytest.raises(AttributeError, match="broken parser internals"):
        parse_content_by_dialect("rule r { condition: true }", "yara", show_status=False)


def test_parse_services_yaral_explicit_and_standard() -> None:
    msgs: list[str] = []
    yaral_code = """
rule ev {
  events:
    $e.metadata.event_type = "X"
  condition:
    $e
}
"""
    ast_yaral, lex_y, par_y = parse_content_by_dialect(
        yaral_code, "yara-l", show_status=True, status_cb=msgs.append
    )
    assert ast_yaral is not None
    assert lex_y == []
    assert par_y == []
    assert any("Using YARA-L parser" in m for m in msgs)

    yara_code = """
rule std {
  condition:
    true
}
"""
    ast_std, lex_s, par_s = parse_content_by_dialect(yara_code, "yara", show_status=False)
    assert ast_std is not None
    assert lex_s == []
    assert par_s == []

    ast_yarax, lex_x, par_x = parse_content_by_dialect(
        _yarax_code(), "yara-x", show_status=True, status_cb=msgs.append
    )
    assert isinstance(ast_yarax.rules[0].condition, WithStatement)
    assert lex_x == []
    assert par_x == []
    assert any("Using YARA-X parser" in m for m in msgs)


@pytest.mark.parametrize("dialect", [None, 123])
def test_parse_services_rejects_non_string_dialects(dialect: object) -> None:
    with pytest.raises(TypeError, match="dialect must be a string"):
        parse_content_by_dialect("rule r { condition: true }", dialect, show_status=False)


@pytest.mark.parametrize("dialect", ["", "xml", "yarax"])
def test_parse_services_rejects_unknown_dialects(dialect: str) -> None:
    with pytest.raises(ValueError, match="dialect must be one of: auto, yara, yara-l, yara-x"):
        parse_content_by_dialect("rule r { condition: true }", dialect, show_status=False)
