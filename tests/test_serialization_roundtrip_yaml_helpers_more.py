"""Additional real coverage for roundtrip_helpers and yaml_serializer."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.errors import SerializationError
from yaraast.serialization.roundtrip_helpers import create_generator, detect_formatting
from yaraast.serialization.roundtrip_models import FormattingInfo, RoundTripMetadata
from yaraast.serialization.yaml_serializer import YamlSerializer


def _sample_ast() -> YaraFile:
    return YaraFile(rules=[Rule(name="r1", condition=BooleanLiteral(value=True))])


def test_detect_formatting_crlf_cr_and_block_comments() -> None:
    crlf = "rule a {\r\n    condition:\r\n        true\r\n}\r\n"
    formatting = detect_formatting(crlf)
    assert formatting.line_endings == "\r\n"

    cr_only = "rule b {\r    condition:\r        true\r}\r"
    formatting = detect_formatting(cr_only)
    assert formatting.line_endings == "\r"

    block = "/* block */\nrule c {\n\tcondition:\n\t\ttrue\n}\n"
    formatting = detect_formatting(block)
    assert formatting.comment_style == "block"
    assert formatting.indent_style == "tabs"

    line_comment = "// line comment\nrule d {\n  condition:\n    true\n}\n"
    formatting = detect_formatting(line_comment)
    assert formatting.comment_style == "line"


def test_create_generator_uses_default_indent_without_original_formatting() -> None:
    metadata = RoundTripMetadata(
        formatting=FormattingInfo(indent_size=2),
        comments_preserved=False,
    )
    generator = create_generator(
        metadata=metadata,
        preserve_original_formatting=False,
        preserve_comments=True,
    )
    assert generator.indent_size == 4
    assert generator.preserve_comments is True


def test_yaml_serializer_error_and_output_paths(tmp_path: Path) -> None:
    serializer = YamlSerializer(include_metadata=True, flow_style=False)
    ast = _sample_ast()

    with pytest.raises(SerializationError, match="No YAML input provided"):
        serializer.deserialize()

    out = tmp_path / "ast.yaml"
    yaml_str = serializer.serialize(ast, output_path=out)
    assert out.exists()
    assert "metadata:" in yaml_str

    restored = serializer.deserialize(input_path=out)
    assert restored.rules[0].name == "r1"

    minimal_out = tmp_path / "minimal.yaml"
    serializer.serialize_minimal(ast, output_path=minimal_out)
    assert minimal_out.exists()

    rules_out = tmp_path / "rules.yaml"
    rules_yaml = serializer.serialize_rules_only(ast, output_path=rules_out)
    assert rules_out.exists()
    data = yaml.safe_load(rules_yaml)
    assert data["rule_count"] == 1


def test_yaml_serializer_without_metadata_skips_yaml_metadata_block() -> None:
    serializer = YamlSerializer(include_metadata=False)
    yaml_str = serializer.serialize(_sample_ast())
    data = yaml.safe_load(yaml_str)
    assert "metadata" not in data
