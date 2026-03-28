"""More tests for serialize services (no mocks)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.cli import serialize_services as ss
from yaraast.errors import ValidationError

YARA_CODE = """
import "pe"

rule one {
  strings:
    $a = "x"
  condition:
    $a
}
""".strip()


def test_serialize_services_export_import_validate_and_info(tmp_path: Path) -> None:
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(YARA_CODE, encoding="utf-8")

    ast = ss.parse_yara_file(yara_path)
    info = ss.build_ast_info(ast)
    assert info["rule_count"] == 1
    assert info["import_count"] == 1
    assert "one" in info["rule_samples"]

    json_out = tmp_path / "ast.json"
    yaml_out = tmp_path / "ast.yaml"
    pbuf_out = tmp_path / "ast.pb"
    ptxt_out = tmp_path / "ast.txt"

    result_json, stats_json = ss.export_ast(ast, "json", str(json_out), minimal=False)
    assert result_json and json_out.exists()
    assert stats_json is None

    result_yaml, _ = ss.export_ast(ast, "yaml", str(yaml_out), minimal=True)
    assert result_yaml and yaml_out.exists()

    result_pbtxt, _ = ss.export_ast(ast, "protobuf", str(ptxt_out), minimal=False)
    assert result_pbtxt and ptxt_out.exists()

    result_pb, stats_pb = ss.export_ast(ast, "protobuf", str(pbuf_out), minimal=False)
    assert result_pb is not None  # protobuf serialization now returns content
    assert stats_pb and isinstance(stats_pb, dict)

    ast_json = ss.import_ast(str(json_out), "json")
    ast_yaml = ss.import_ast(str(yaml_out), "yaml")
    ast_pb = ss.import_ast(str(pbuf_out), "protobuf")
    assert len(ast_json.rules) == len(ast_yaml.rules) == len(ast_pb.rules) == 1

    validated = ss.validate_serialized(json_out, "json")
    assert len(validated.rules) == 1


def test_serialize_services_compare_and_error_paths(tmp_path: Path) -> None:
    old_file = tmp_path / "old.yar"
    new_file = tmp_path / "new.yar"
    old_file.write_text("rule a { condition: true }", encoding="utf-8")
    new_file.write_text("rule a { condition: false }", encoding="utf-8")

    differ, diff = ss.compare_yara_files(old_file, new_file)
    assert differ is not None
    assert diff is not None

    ast = ss.parse_yara_file(old_file)

    with pytest.raises(ValidationError, match="Unknown format"):
        ss.export_ast(ast, "badfmt", None, minimal=False)

    with pytest.raises(ValidationError, match="Unknown format"):
        ss.import_ast(str(old_file), "badfmt")
