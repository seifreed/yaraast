from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest

import yaraast

SOURCE = "rule example { condition: true }"


def test_parse_and_format_public_api(tmp_path: Path) -> None:
    document = yaraast.parse(SOURCE)
    assert document.rules[0].name == "example"
    assert yaraast.parse(yaraast.format(SOURCE)).rules[0].name == "example"

    rule_path = tmp_path / "example.yar"
    rule_path.write_text(SOURCE, encoding="utf-8")
    assert yaraast.parse_file(rule_path).rules[0].name == "example"


@pytest.mark.parametrize(
    ("dialect", "source", "expected"),
    [
        (
            "yara-x",
            "rule x { condition: with value = 1: value == 1 }",
            "with value = 1",
        ),
        (
            "yara-l",
            'rule l { events: $e.metadata.event_type = "x" condition: $e }',
            "events:",
        ),
    ],
)
def test_format_dispatches_to_dialect_generator(
    dialect: Literal["yara-x", "yara-l"], source: str, expected: str
) -> None:
    formatted = yaraast.format(source, dialect=dialect)
    assert expected in formatted
    assert yaraast.parse(formatted, dialect=dialect).rules


@pytest.mark.parametrize("function_name", ["parse", "parse_file", "format"])
def test_public_api_rejects_unknown_dialect(function_name: str, tmp_path: Path) -> None:
    function = getattr(yaraast, function_name)
    argument = tmp_path / "example.yar" if function_name == "parse_file" else SOURCE
    with pytest.raises(ValueError, match="dialect must be one of"):
        function(argument, dialect="unknown")
