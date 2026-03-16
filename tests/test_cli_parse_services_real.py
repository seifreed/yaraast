"""Real integration tests for CLI parse services without test doubles."""

from __future__ import annotations

from yaraast.cli.parse_services import parse_content_by_dialect


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


def test_parse_services_auto_yara_invalid_fallback() -> None:
    ast, lex, par = parse_content_by_dialect("rule broken { condition:", "auto", show_status=False)
    assert ast is not None
    assert isinstance(lex, list)
    assert isinstance(par, list)


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
