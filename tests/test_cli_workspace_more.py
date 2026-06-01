"""Real CLI tests for workspace commands (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.workspace import workspace


def _write(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content), encoding="utf-8")
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


def test_workspace_analyze_text_and_json(tmp_path: Path) -> None:
    _write(tmp_path, "a.yar", _sample_yara("a"))
    _write(tmp_path, "b.yar", _sample_yara("b"))
    yara_path = _write(tmp_path, "c.yara", _sample_yara("c"))

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

    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert "statistics" in payload
    assert "files" in payload
    assert yara_path in payload["files"]


def test_workspace_graph_json(tmp_path: Path) -> None:
    _write(tmp_path, "a.yar", _sample_yara("a"))
    _write(tmp_path, "b.yara", _sample_yara("b"))

    out_path = tmp_path / "graph.json"
    runner = CliRunner()

    result = runner.invoke(
        workspace,
        ["graph", str(tmp_path), "--format", "json", "--output", str(out_path)],
    )

    assert result.exit_code == 0
    assert out_path.exists()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert "nodes" in payload
    assert any(path.endswith("b.yara") for path in payload["nodes"])


def test_workspace_rejects_empty_output_path(tmp_path: Path) -> None:
    _write(tmp_path, "a.yar", _sample_yara("a"))
    runner = CliRunner()

    analyze_result = runner.invoke(
        workspace,
        ["analyze", str(tmp_path), "--format", "json", "--output", ""],
    )
    assert analyze_result.exit_code != 0
    assert "path must not be empty" in analyze_result.output

    graph_result = runner.invoke(
        workspace,
        ["graph", str(tmp_path), "--format", "json", "--output", ""],
    )
    assert graph_result.exit_code != 0
    assert "path must not be empty" in graph_result.output


def test_workspace_rejects_directory_output_path(tmp_path: Path) -> None:
    _write(tmp_path, "a.yar", _sample_yara("a"))
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    runner = CliRunner()

    analyze_result = runner.invoke(
        workspace,
        ["analyze", str(tmp_path), "--format", "json", "--output", str(output_dir)],
    )
    assert analyze_result.exit_code == 2
    assert "output path must not be a directory" in analyze_result.output
    assert "Analyzing directory" not in analyze_result.output

    graph_result = runner.invoke(
        workspace,
        ["graph", str(tmp_path), "--format", "json", "--output", str(output_dir)],
    )
    assert graph_result.exit_code == 2
    assert "output path must not be a directory" in graph_result.output
    assert "Building dependency graph" not in graph_result.output
