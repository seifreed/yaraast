from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest

import yaraast

SOURCE = "rule example { condition: true }"


def test_parse_generate_and_format_public_api(tmp_path: Path) -> None:
    document = yaraast.parse(SOURCE)
    assert document.rules[0].name == "example"
    assert yaraast.parse(yaraast.generate(document)).rules[0].name == "example"
    assert yaraast.parse(yaraast.format_canonical(SOURCE)).rules[0].name == "example"

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
    formatted = yaraast.format_canonical(source, dialect=dialect)
    assert expected in formatted
    assert yaraast.parse(formatted, dialect=dialect).rules


@pytest.mark.parametrize("function_name", ["parse", "parse_file", "format_canonical"])
def test_public_api_rejects_unknown_dialect(function_name: str, tmp_path: Path) -> None:
    function = getattr(yaraast, function_name)
    argument = tmp_path / "example.yar" if function_name == "parse_file" else SOURCE
    with pytest.raises(ValueError, match="dialect must be one of"):
        function(argument, dialect="unknown")


def test_rewrite_lossless_changes_only_selected_utf8_bytes() -> None:
    source = "// keep\nrule café {\n  condition: true  // keep spacing\n}\n"
    encoded = source.encode("utf-8")
    old = b"true"
    start = encoded.index(old)

    rewritten = yaraast.rewrite_lossless(
        source,
        [yaraast.SourceEdit(start=start, end=start + len(old), replacement="false")],
    )

    assert rewritten == source.replace("true", "false")
    assert rewritten.encode("utf-8")[:start] == encoded[:start]
    assert rewritten.endswith("  // keep spacing\n}\n")


def test_rewrite_lossless_rejects_overlap_and_split_utf8_offsets() -> None:
    with pytest.raises(ValueError, match="must not overlap"):
        yaraast.rewrite_lossless(
            "abcdef",
            [yaraast.SourceEdit(1, 4, "x"), yaraast.SourceEdit(3, 5, "y")],
        )

    with pytest.raises(ValueError, match="UTF-8 code point boundaries"):
        yaraast.rewrite_lossless("é", [yaraast.SourceEdit(0, 1, "")])
