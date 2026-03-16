"""More tests for serialize reporting helpers (no mocks)."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from yaraast.cli import serialize_reporting as sr


def test_display_export_import_and_diff_messages(tmp_path: Path) -> None:
    console = Console(record=True, width=120)

    sr.display_export_result(console, '{\n  "a":1\n}', "json", output=None, pretty=True, stats=None)
    sr.display_export_result(
        console,
        None,
        "protobuf",
        output=None,
        pretty=False,
        stats={
            "binary_size_bytes": 10,
            "text_size_bytes": 20,
            "compression_ratio": 2.0,
            "rules_count": 1,
            "imports_count": 0,
        },
    )
    sr.display_export_result(console, None, "json", output="out.json", pretty=False, stats=None)

    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import BooleanLiteral
    from yaraast.ast.rules import Import, Rule

    ast = YaraFile(
        imports=[Import("pe")],
        rules=[
            Rule(name="a", condition=BooleanLiteral(True)),
            Rule(name="b", condition=BooleanLiteral(True)),
        ],
    )
    sr.display_import_result(console, "in.json", "json", ast, output=None)
    sr.display_import_result(console, "in.json", "json", ast, output="out.yar")

    sr.display_diff_no_changes(console)
    sr.display_diff_saved(console, "diff.patch", patch=True)
    sr.display_diff_saved(console, "diff.json", patch=False)

    out = console.export_text()
    assert "AST serialized successfully" in out
    assert "AST exported to out.json" in out
    assert "AST imported from in.json" in out
    assert "Code generation not yet implemented" in out
    assert "No differences found" in out
    assert "Patch file created" in out
    assert "Diff saved to" in out


def test_write_diff_output_and_display_info(tmp_path: Path) -> None:
    diff_data = {"changes": [{"path": "/r/1"}], "summary": {"added": 1}}
    json_out = tmp_path / "d.json"
    yaml_out = tmp_path / "d.yaml"

    sr.write_diff_output(str(json_out), "json", diff_data)
    sr.write_diff_output(str(yaml_out), "yaml", diff_data)

    assert '"changes"' in json_out.read_text(encoding="utf-8")
    assert "changes:" in yaml_out.read_text(encoding="utf-8")

    console = Console(record=True, width=120)
    info_data = {
        "rule_samples": ["a", "b", "c", "d"],
        "rule_count": 4,
        "import_count": 1,
        "include_count": 1,
        "import_list": ["pe"],
        "include_list": ["common.yar"],
        "rule_details": [
            {"name": "a", "strings": 1, "tags": 0, "meta": 1, "modifiers": "none"},
            {"name": "b", "strings": 2, "tags": 1, "meta": 0, "modifiers": "private"},
        ],
        "has_more_rules": True,
        "ast_hash": "hash123",
    }

    sr.display_info(console, str(tmp_path / "in.yar"), info_data)
    text = console.export_text()
    assert "AST Information" in text
    assert "Rule Analysis" in text
    assert "hash123" in text
