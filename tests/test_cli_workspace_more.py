"""Real CLI tests for workspace commands (no mocks)."""

from __future__ import annotations

import json
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.workspace import workspace


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def _sample_yara(rule_name: str = "sample") -> str:
    return f"""
    rule {rule_name} {{
        strings:
            $a = \"abc\"
        condition:
            $a
    }}
    """


def test_workspace_analyze_text_and_json(tmp_path) -> None:
    _write(tmp_path, "a.yar", _sample_yara("a"))
    _write(tmp_path, "b.yar", _sample_yara("b"))

    runner = CliRunner()

    text = runner.invoke(workspace, ["analyze", str(tmp_path), "--format", "text"])
    assert text.exit_code == 0
    assert "Workspace Analysis Report" in text.output

    out_path = tmp_path / "report.json"
    json_run = runner.invoke(
        workspace,
        ["analyze", str(tmp_path), "--format", "json", "--output", str(out_path)],
    )
    assert json_run.exit_code == 0
    assert out_path.exists()

    payload = json.loads(out_path.read_text())
    assert "statistics" in payload
    assert "files" in payload


def test_workspace_graph_json(tmp_path) -> None:
    _write(tmp_path, "a.yar", _sample_yara("a"))

    out_path = tmp_path / "graph.json"
    runner = CliRunner()

    result = runner.invoke(
        workspace,
        ["graph", str(tmp_path), "--format", "json", "--output", str(out_path)],
    )

    assert result.exit_code == 0
    assert out_path.exists()
    payload = json.loads(out_path.read_text())
    assert "nodes" in payload
