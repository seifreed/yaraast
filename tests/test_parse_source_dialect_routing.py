"""parse_source routes every supported dialect, including YARA-L."""

from __future__ import annotations

from yaraast import YaraLFile, parse_source
from yaraast.ast.base import YaraFile

_CLASSIC = 'rule classic { strings: $a = "x" condition: $a }'
_YARA_X = "rule x { condition: for any i in (0..10) : (i == 1) }"
_YARA_L = (
    "rule yl {\n"
    "  meta:\n"
    '    author = "x"\n'
    "  events:\n"
    '    $e.metadata.event_type = "NETWORK_CONNECTION"\n'
    "  condition:\n"
    "    $e\n"
    "}"
)


def test_parse_source_routes_classic_to_yara_file() -> None:
    result = parse_source(_CLASSIC)
    assert isinstance(result, YaraFile)
    assert result.rules[0].name == "classic"


def test_parse_source_routes_yara_l_to_yaral_file() -> None:
    result = parse_source(_YARA_L)
    assert isinstance(result, YaraLFile)
