"""Regression tests for YARA-L string-literal values that begin with ``$``/``%``.

A quoted string whose content starts with ``$`` or ``%`` must round-trip as a
quoted string. Before the fix it was stored as a bare ``str`` and the generator
re-emitted it unquoted, producing invalid YARA-L (``$e.x = $100``) that either
failed to reparse or silently became a reference (``%list%``).
"""

from __future__ import annotations

from dataclasses import asdict

import pytest

from yaraast.yaral.ast_nodes import YaraLFile
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.parser import YaraLParser

PARSERS = [EnhancedYaraLParser, YaraLParser]

DOLLAR_EVENT = 'rule r {\n  events:\n    $e.x = "$100 cost"\n  condition:\n    $e\n}'
PERCENT_EVENT = 'rule r {\n  events:\n    $e.x = "%SystemRoot%"\n  condition:\n    $e\n}'
DOLLAR_CONDITION = 'rule r {\n  events:\n    $e.x = "a"\n  condition:\n    $v = "$ref"\n}'
DOLLAR_OUTCOME = (
    'rule r {\n  events:\n    $e.x = "a"\n  outcome:\n    $label = "$tag"\n  condition:\n    $e\n}'
)


type ParserType = type[EnhancedYaraLParser] | type[YaraLParser]


def _parse(parser_cls: ParserType, source: str) -> YaraLFile:
    return parser_cls(source).parse()


def _generate(parser_cls: ParserType, source: str) -> str:
    return YaraLGenerator().generate(_parse(parser_cls, source))


@pytest.mark.parametrize("parser_cls", PARSERS)
@pytest.mark.parametrize(
    ("source", "needle"),
    [
        (DOLLAR_EVENT, '"$100 cost"'),
        (PERCENT_EVENT, '"%SystemRoot%"'),
        (DOLLAR_CONDITION, '"$ref"'),
        (DOLLAR_OUTCOME, '"$tag"'),
    ],
)
def test_special_prefixed_string_literal_stays_quoted(
    parser_cls: ParserType, source: str, needle: str
) -> None:
    generated = _generate(parser_cls, source)
    assert needle in generated
    # The bare unquoted form is what the old generator produced and is invalid.
    assert needle.strip('"') + "\n" not in generated.replace(needle, "")
    # And it must reparse and regenerate identically.
    reparsed = _generate(parser_cls, generated)
    assert reparsed == generated


@pytest.mark.parametrize("parser_cls", PARSERS)
def test_bare_reference_value_is_not_quoted(parser_cls: ParserType) -> None:
    generated = _generate(parser_cls, "rule r {\n  events:\n    $e.x = $v\n  condition:\n    $e\n}")
    assert "$e.x = $v" in generated
    assert '"$v"' not in generated


@pytest.mark.parametrize("parser_cls", PARSERS)
def test_reference_list_value_is_preserved(parser_cls: ParserType) -> None:
    generated = _generate(
        parser_cls, "rule r {\n  events:\n    $e.x in %list%\n  condition:\n    $e\n}"
    )
    assert "%list%" in generated
    assert '"%list%"' not in generated


def test_marker_values_are_yaml_serializable() -> None:
    yaml = pytest.importorskip("yaml")
    source = 'rule r {\n  events:\n    $e.x = "$100"\n    $e.y = (1 + 2)\n  condition:\n    $e\n}'
    ast = EnhancedYaraLParser(source).parse()
    dumped = yaml.safe_dump(asdict(ast))
    assert "$100" in dumped
