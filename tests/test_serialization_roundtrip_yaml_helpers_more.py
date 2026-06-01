"""Additional real coverage for roundtrip_helpers and yaml_serializer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.errors import SerializationError
from yaraast.serialization.roundtrip_helpers import create_generator, detect_formatting
from yaraast.serialization.roundtrip_models import FormattingInfo, RoundTripMetadata
from yaraast.serialization.roundtrip_pipeline_helpers import dump_pipeline_yaml
from yaraast.serialization.yaml_serializer import YamlSerializer
from yaraast.serialization.yaml_serializer_helpers import dump_yaml


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


@pytest.mark.parametrize("invalid_rules", ["", False, 0, None])
def test_yaml_serializer_rules_only_rejects_invalid_rule_collections(
    invalid_rules: Any,
) -> None:
    ast = _sample_ast()
    cast(Any, ast).rules = invalid_rules

    with pytest.raises(SerializationError, match="YaraFile rules"):
        YamlSerializer().serialize_rules_only(ast)


def test_yaml_serializer_rules_only_rejects_invalid_rule_items() -> None:
    ast = _sample_ast()
    cast(Any, ast).rules = [object()]

    with pytest.raises(SerializationError, match="YaraFile rules item"):
        YamlSerializer().serialize_rules_only(ast)


def test_yaml_helpers_emit_safe_loadable_sequence_data_without_python_tags() -> None:
    data = {"values": ("alpha", "beta")}

    yaml_str = dump_yaml(data, flow_style=False)
    assert "!!python/" not in yaml_str
    assert yaml.safe_load(yaml_str) == {"values": ["alpha", "beta"]}

    pipeline_yaml = dump_pipeline_yaml(data, output_path=None)
    assert "!!python/" not in pipeline_yaml
    assert yaml.safe_load(pipeline_yaml) == {"values": ["alpha", "beta"]}


@pytest.mark.parametrize("flow_style", [None, 123, "yes"])
def test_dump_yaml_rejects_invalid_flow_style(flow_style: object) -> None:
    with pytest.raises(TypeError, match="flow_style must be a boolean"):
        dump_yaml({"a": 1}, flow_style=flow_style)
