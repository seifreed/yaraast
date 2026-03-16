"""CLI tests for workspace command."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.workspace import workspace


def _write_file(path, content: str) -> None:
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")


def test_workspace_analyze_and_graph(tmp_path) -> None:
    yara_dir = tmp_path / "rules"
    yara_dir.mkdir()

    rule_path = yara_dir / "main.yar"
    _write_file(
        rule_path,
        """
        rule main_rule {
            condition:
                true
        }
        """,
    )

    runner = CliRunner()
    result = runner.invoke(
        workspace,
        ["analyze", str(yara_dir), "--format", "json", "--no-recursive"],
    )
    assert result.exit_code == 0
    assert "Workspace Analysis Report" not in result.output
    assert "statistics" in result.output

    output_path = tmp_path / "graph.json"
    result = runner.invoke(
        workspace,
        ["graph", str(yara_dir), "--format", "json", "--output", str(output_path)],
    )
    assert result.exit_code == 0
    assert output_path.exists()


def test_workspace_resolve_with_tree(tmp_path) -> None:
    include_path = tmp_path / "included.yar"
    _write_file(
        include_path,
        """
        rule included_rule {
            condition:
                true
        }
        """,
    )

    main_path = tmp_path / "main.yar"
    _write_file(
        main_path,
        """
        include "included.yar"

        rule main_rule {
            condition:
                true
        }
        """,
    )

    runner = CliRunner()
    result = runner.invoke(
        workspace,
        ["resolve", str(main_path), "--show-tree"],
    )
    assert result.exit_code == 0
    assert "Successfully resolved" in result.output
    assert "Total files in resolution cache" in result.output
