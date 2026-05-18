"""Additional tests for YARA-L parser entrypoints."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import EventAssignment
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
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


def test_yaral_parsers_accept_decimal_literals_in_value_sections() -> None:
    code = (
        "rule decimals { meta: score = 3.14 events: $e.metadata.score = 2.5 "
        "condition: $e options: threshold = 1.5 }"
    )

    classic = YaraLParser(code).parse().rules[0]
    enhanced_parser = EnhancedYaraLParser(code)
    enhanced = enhanced_parser.parse().rules[0]

    assert classic.meta is not None
    assert classic.events is not None
    assert classic.options is not None
    classic_event = classic.events.statements[0]
    assert isinstance(classic_event, EventAssignment)
    assert classic.meta.entries[0].value == 3.14
    assert classic_event.value == 2.5
    assert classic.options.options["threshold"] == 1.5

    assert enhanced_parser.errors == []
    assert enhanced.meta is not None
    assert enhanced.events is not None
    assert enhanced.options is not None
    enhanced_event = enhanced.events.statements[0]
    assert isinstance(enhanced_event, EventAssignment)
    assert enhanced.meta.entries[0].value == 3.14
    assert enhanced_event.value == 2.5
    assert enhanced.options.options["threshold"] == 1.5
