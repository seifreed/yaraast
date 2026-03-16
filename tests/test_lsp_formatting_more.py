"""Real tests for LSP formatting (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.formatting import FormattingProvider
from yaraast.lsp.runtime import LspRuntime


def test_formatting_returns_edit() -> None:
    provider = FormattingProvider()
    text = 'rule a { strings: $a = "abc" condition: $a }'

    edits = provider.format_document(text)
    assert edits
    assert edits[0].new_text


def test_formatting_range_delegates() -> None:
    provider = FormattingProvider()
    text = "rule b { condition: true }"

    edits = provider.format_range(
        text, Position(line=0, character=0), Position(line=0, character=4)
    )
    assert edits


def test_formatting_uses_runtime_code_formatting_config() -> None:
    runtime = LspRuntime()
    runtime.update_config(
        {
            "YARA": {
                "codeFormatting": {
                    "brace_style": "new_line",
                    "indent_size": 2,
                    "space_before_colon": False,
                    "space_after_colon": True,
                }
            }
        }
    )
    provider = FormattingProvider(runtime)
    uri = "file:///sample.yar"
    text = "rule a : tag { condition: true }"

    edits = provider.format_document(text, uri)
    assert edits
    formatted = edits[0].new_text
    assert "rule a: tag" in formatted
    assert "{\n" in formatted


def test_formatting_range_formats_enclosing_rule_only() -> None:
    runtime = LspRuntime()
    provider = FormattingProvider(runtime)
    uri = "file:///sample.yar"
    text = """
rule a { condition: true }

rule b { condition: true }
""".lstrip()

    edits = provider.format_range(
        text,
        Position(line=2, character=8),
        Position(line=2, character=12),
        uri,
    )
    assert edits
    assert len(edits) == 1
    assert edits[0].range.start.line == 2
    assert edits[0].range.end.line == 2
