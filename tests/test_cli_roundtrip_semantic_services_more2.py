from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from yaraast.ast.base import YaraFile
from yaraast.cli.roundtrip_services import (
    deserialize_roundtrip_file,
    pipeline_serialize_file,
    pretty_print_file,
    serialize_roundtrip_file,
    test_roundtrip_file as run_roundtrip_file_test,
)
from yaraast.cli.semantic_services import _create_validation_context, _process_file
from yaraast.errors import ValidationError
from yaraast.parser import Parser
from yaraast.serialization.roundtrip_serializer import EnhancedYamlSerializer
from yaraast.yarax.ast_nodes import WithStatement
from yaraast.yarax.parser import YaraXParser


def _write_rule(path: Path) -> None:
    path.write_text(
        """
rule sample {
    strings:
        $a = "abc"
    condition:
        $a
}
""".strip(),
        encoding="utf-8",
    )


def _write_yarax_rule(path: Path) -> None:
    path.write_text(
        """
rule yarax_sample {
    condition:
        with xs = [1]: match xs { _ => true }
}
""".strip(),
        encoding="utf-8",
    )


def test_roundtrip_service_end_to_end_variants(tmp_path: Path) -> None:
    yara_path = tmp_path / "sample.yar"
    _write_rule(yara_path)

    ast, payload = serialize_roundtrip_file(
        yara_path,
        "json",
        preserve_comments=True,
        preserve_formatting=True,
    )
    assert ast.rules[0].name == "sample"
    assert json.loads(payload)["ast"]["type"] == "YaraFile"

    serialized_path = tmp_path / "sample.json"
    serialized_path.write_text(payload, encoding="utf-8")
    restored_ast, generated = deserialize_roundtrip_file(serialized_path, "json", True)
    assert restored_ast.rules[0].name == "sample"
    assert "rule sample" in generated

    test_result = run_roundtrip_file_test(yara_path, "json")
    assert test_result["metadata"]["original_rule_count"] == 1


def test_roundtrip_pipeline_and_manifest_services(tmp_path: Path) -> None:
    yara_path = tmp_path / "sample.yar"
    _write_rule(yara_path)

    ast, yaml_content, pipeline_data = pipeline_serialize_file(
        yara_path,
        '{"ci":"true"}',
    )
    assert ast.rules[0].name == "sample"
    assert pipeline_data == {"ci": "true"}
    loaded = yaml.safe_load(yaml_content)
    assert loaded["pipeline_metadata"]["ci"] == "true"

    manifest = EnhancedYamlSerializer().serialize_rules_manifest(ast)
    manifest_data = yaml.safe_load(manifest)
    assert manifest_data["summary"]["total_rules"] == 1


@pytest.mark.parametrize("pipeline_info", ['"ci"', "[1]", "42"])
def test_pipeline_serialize_file_rejects_non_object_pipeline_info(
    tmp_path: Path,
    pipeline_info: str,
) -> None:
    yara_path = tmp_path / "sample.yar"
    _write_rule(yara_path)

    with pytest.raises(ValidationError, match="pipeline_info must be a JSON object"):
        pipeline_serialize_file(yara_path, pipeline_info)


def test_pipeline_serialize_file_rejects_invalid_pipeline_info_json(tmp_path: Path) -> None:
    yara_path = tmp_path / "sample.yar"
    _write_rule(yara_path)

    with pytest.raises(ValidationError, match="pipeline_info must be valid JSON"):
        pipeline_serialize_file(yara_path, "{bad json")


@pytest.mark.parametrize("pipeline_info", [False, 0, [], object()])
def test_pipeline_serialize_file_rejects_non_string_pipeline_info(
    tmp_path: Path,
    pipeline_info: Any,
) -> None:
    yara_path = tmp_path / "sample.yar"
    _write_rule(yara_path)

    with pytest.raises(TypeError, match="pipeline_info must be a string"):
        pipeline_serialize_file(yara_path, cast(str | None, pipeline_info))


def test_roundtrip_pretty_print_compact_and_verbose_styles(tmp_path: Path) -> None:
    yara_path = tmp_path / "styles.yar"
    _write_rule(yara_path)

    ast_compact, compact = pretty_print_file(
        yara_path, "compact", 2, 80, False, False, False, False
    )
    assert ast_compact.rules[0].name == "sample"
    assert "rule sample" in compact

    ast_verbose, verbose = pretty_print_file(
        yara_path, "verbose", 4, 120, False, False, False, False
    )
    assert ast_verbose.rules[0].name == "sample"
    assert "condition:" in verbose


def test_roundtrip_pretty_and_pipeline_services_parse_yarax(tmp_path: Path) -> None:
    yara_path = tmp_path / "yarax.yar"
    _write_yarax_rule(yara_path)

    pretty_ast, pretty_output = pretty_print_file(
        yara_path, "readable", 4, 120, False, False, False, False
    )
    assert isinstance(pretty_ast.rules[0].condition, WithStatement)
    assert "with xs = [1]" in pretty_output
    assert "match xs" in pretty_output
    assert "        _ => true," in pretty_output
    assert "    }\n}" in pretty_output
    YaraXParser(pretty_output).parse()

    pipeline_ast, yaml_content, pipeline_data = pipeline_serialize_file(yara_path, None)
    assert isinstance(pipeline_ast.rules[0].condition, WithStatement)
    assert pipeline_data is None
    loaded = yaml.safe_load(yaml_content)
    assert loaded["ast"]["rules"][0]["condition"]["type"] == "WithStatement"


def test_semantic_process_file_updates_existing_ast_location(tmp_path: Path) -> None:
    file_path = tmp_path / "semantic_loc.yar"
    _write_rule(file_path)

    context = _create_validation_context()
    ast = Parser().parse(file_path.read_text(encoding="utf-8"))
    from yaraast.ast.base import Location

    ast.location = Location(line=1, column=1, file=None)

    class ParserWithPresetAst:
        def parse(self, _content: str) -> YaraFile:
            return ast

    result = _process_file(file_path, ParserWithPresetAst(), context["validator"])

    assert result is not None
    assert ast.location.file == str(file_path)
