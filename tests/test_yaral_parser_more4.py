"""Additional tests for YARA-L parser entrypoints."""

from __future__ import annotations

from yaraast.yaral.parser import BaseTokenType, YaraLParser, YaraLToken, __all__


def test_yaral_parser_skips_unknown_tokens_before_rule() -> None:
    code = 'garbage tokens here\nrule x { events: $e.metadata.event_type = "A" condition: $e }'
    ast = YaraLParser(code).parse()
    assert len(ast.rules) == 1
    assert ast.rules[0].name == "x"


def test_yaral_parser_exports() -> None:
    assert "YaraLParser" in __all__
    assert BaseTokenType is not None
    assert YaraLToken is not None
