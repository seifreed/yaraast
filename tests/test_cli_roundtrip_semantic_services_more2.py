from __future__ import annotations

import json
from pathlib import Path

import yaml

from yaraast.cli.roundtrip_services import (
    build_rules_manifest,
    deserialize_roundtrip_file,
    pipeline_serialize_file,
    serialize_roundtrip_file,
)
from yaraast.cli.roundtrip_services import test_roundtrip_file as run_roundtrip_file_test
from yaraast.cli.semantic_services import _create_validation_context, _process_file
from yaraast.parser import Parser


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

    manifest = build_rules_manifest(ast)
    manifest_data = yaml.safe_load(manifest)
    assert manifest_data["summary"]["total_rules"] == 1


def test_roundtrip_pretty_print_compact_and_verbose_styles(tmp_path: Path) -> None:
    from yaraast.cli.roundtrip_services import pretty_print_file

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


def test_semantic_process_file_updates_existing_ast_location(tmp_path: Path) -> None:
    file_path = tmp_path / "semantic_loc.yar"
    _write_rule(file_path)

    context = _create_validation_context()
    ast = Parser().parse(file_path.read_text(encoding="utf-8"))
    from yaraast.ast.base import Location

    ast.location = Location(line=1, column=1, file=None)

    class ParserWithPresetAst:
        def parse(self, _content: str):
            return ast

    result = _process_file(file_path, ParserWithPresetAst(), context["validator"])

    assert result is not None
    assert ast.location.file == str(file_path)
