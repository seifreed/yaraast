from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.workspace import workspace


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_workspace_resolve_error_paths_and_no_tree(tmp_path: Path) -> None:
    runner = CliRunner()
    missing_include = tmp_path / "missing_include.yar"
    recursive_a = tmp_path / "a.yar"
    recursive_b = tmp_path / "b.yar"

    _write(
        missing_include,
        """
include "nope.yar"
    rule a { condition: true }
""",
    )
    _write(
        recursive_a,
        """
include "b.yar"
rule a { condition: true }
""",
    )
    _write(
        recursive_b,
        """
include "a.yar"
    rule b { condition: true }
""",
    )

    no_tree = runner.invoke(workspace, ["resolve", str(missing_include), "--no-tree"])
    assert no_tree.exit_code == 0
    assert "Successfully resolved" in no_tree.output
    assert "Total files in resolution cache" in no_tree.output

    recursive = runner.invoke(workspace, ["resolve", str(recursive_a)])
    assert recursive.exit_code != 0
    assert "Error:" in recursive.output


def test_workspace_graph_stdout_dot_path(tmp_path: Path) -> None:
    runner = CliRunner()
    _write(
        tmp_path / "ok.yar",
        """
rule ok {
    condition:
        true
}
""",
    )

    result = runner.invoke(workspace, ["graph", str(tmp_path)])
    assert result.exit_code == 0
    assert "Building dependency graph for" in result.output
    assert "digraph" in result.output or "ok.yar" in result.output

    out = tmp_path / "graph.dot"
    dot_result = runner.invoke(
        workspace, ["graph", str(tmp_path), "--output", str(out), "--format", "dot"]
    )
    assert dot_result.exit_code == 0
    assert out.exists()
    assert "Graph written to" in dot_result.output
    assert "Visualize with: dot -Tpng" in dot_result.output
