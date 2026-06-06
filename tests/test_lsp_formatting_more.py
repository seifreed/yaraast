"""Real tests for LSP formatting (no mocks)."""

from __future__ import annotations

from typing import Any, cast

from lsprotocol.types import Position
import pytest

from yaraast.lsp.formatting import FormattingProvider
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.utf16 import utf8_col_to_utf16


@pytest.mark.parametrize("text", [None, 1, b"rule a", object()])
def test_formatting_rejects_non_string_text(text: Any) -> None:
    provider = FormattingProvider()

    with pytest.raises(TypeError, match="Formatting text must be a string"):
        provider.format_document(cast(str, text))

    with pytest.raises(TypeError, match="Formatting text must be a string"):
        provider.format_range(
            cast(str, text),
            Position(line=0, character=0),
            Position(line=0, character=1),
        )


def test_formatting_rejects_invalid_uri() -> None:
    provider = FormattingProvider()

    with pytest.raises(TypeError, match="Formatting URI must be a string or None"):
        provider.format_document("rule a { condition: true }", cast(str, object()))

    with pytest.raises(TypeError, match="Formatting URI must be a string or None"):
        provider.format_range(
            "rule a { condition: true }",
            Position(line=0, character=0),
            Position(line=0, character=1),
            cast(str, object()),
        )


def test_formatting_rejects_invalid_range_positions() -> None:
    provider = FormattingProvider()

    with pytest.raises(TypeError, match="format range start must be an LSP Position"):
        provider.format_range(
            "rule a { condition: true }",
            cast(Any, object()),
            Position(line=0, character=1),
        )

    with pytest.raises(TypeError, match="format range end must be an LSP Position"):
        provider.format_range(
            "rule a { condition: true }",
            Position(line=0, character=0),
            cast(Any, object()),
        )


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


def test_formatting_ignores_invalid_runtime_enum_config() -> None:
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"codeFormatting": {"brace_style": "diagonal"}}})
    provider = FormattingProvider(runtime)

    edits = provider.format_document("rule a { condition: true }", "file:///sample.yar")

    assert edits
    assert "rule a" in edits[0].new_text


def test_formatting_ignores_incomplete_runtime_section_order() -> None:
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"codeFormatting": {"section_order": ["meta"]}}})
    provider = FormattingProvider(runtime)
    text = 'rule a { meta: author = "me" strings: $a = "x" condition: $a }'

    edits = provider.format_document(text, "file:///sample.yar")

    assert edits
    formatted = edits[0].new_text
    assert "meta:" in formatted
    assert "strings:" in formatted
    assert "condition:" in formatted


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


def test_formatting_edit_ranges_use_utf16_columns() -> None:
    provider = FormattingProvider()
    text = "rule a { condition: true } // 😀😀"
    line = text.splitlines()[0]

    document_edits = provider.format_document(text)
    range_edits = provider.format_range(
        text,
        Position(line=0, character=8),
        Position(line=0, character=12),
    )

    expected_end = utf8_col_to_utf16(line, len(line))
    assert document_edits
    assert document_edits[0].range.end.character == expected_end
    assert range_edits
    assert range_edits[0].range.end.character == expected_end
