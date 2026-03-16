"""More real tests for metrics/optimize/performance reporting CLI modules."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli import performance_reporting as pr
from yaraast.cli.commands.metrics import metrics
from yaraast.cli.commands.optimize import optimize


def _write_metrics_rule(tmp_path: Path) -> Path:
    path = tmp_path / "sample_more.yar"
    path.write_text(
        """
import "pe"

rule dep_target {
    condition:
        true
}

rule sample_more {
    strings:
        $a = "abc"
        $b = { 4D 5A ?? 90 }
        $c = /ab+c/
    condition:
        dep_target and $a and pe.is_pe
}
""".strip(),
        encoding="utf-8",
    )
    return path


def test_metrics_commands_more_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = _write_metrics_rule(tmp_path)

    res = runner.invoke(metrics, ["complexity", str(yara_path), "--quality-gate", "101"])
    assert res.exit_code == 0
    assert "Quality gate warning" in res.output

    res = runner.invoke(metrics, ["graph", str(yara_path), "-t", "full", "-f", "dot"])
    assert res.exit_code == 0
    assert "Graph source:" in res.output

    res = runner.invoke(metrics, ["graph", str(yara_path), "-t", "modules", "-f", "dot"])
    assert res.exit_code == 0
    assert "Dependency graph generated" in res.output

    res = runner.invoke(metrics, ["graph", str(yara_path), "-t", "complexity", "-f", "dot"])
    assert res.exit_code == 0
    assert "Dependency graph generated" in res.output

    res = runner.invoke(metrics, ["patterns", str(yara_path), "-t", "complexity", "-f", "dot"])
    assert res.exit_code == 0
    assert "Pattern diagram generated" in res.output

    res = runner.invoke(metrics, ["patterns", str(yara_path), "-t", "similarity", "-f", "dot"])
    assert res.exit_code == 0
    assert "Pattern diagram generated" in res.output

    res = runner.invoke(metrics, ["patterns", str(yara_path), "-t", "hex", "-f", "dot", "--stats"])
    assert res.exit_code == 0
    assert "Pattern Statistics:" in res.output

    with runner.isolated_filesystem(temp_dir=tmp_path):
        res = runner.invoke(metrics, ["report", str(yara_path), "-f", "svg"])
        assert res.exit_code == 0
        report_dir = Path("sample_more_metrics_report")
        assert report_dir.exists()
        assert (report_dir / "summary.json").exists()
        assert "Generated 9 files" in res.output


def test_metrics_tree_default_output_and_strings_output_file(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = _write_metrics_rule(tmp_path)

    with runner.isolated_filesystem(temp_dir=tmp_path):
        res = runner.invoke(metrics, ["tree", str(yara_path), "--interactive"])
        assert res.exit_code == 0
        default_output = Path("sample_more_interactive.html")
        assert default_output.exists()
        assert "File size:" in res.output

    strings_out = tmp_path / "strings_report.txt"
    res = runner.invoke(metrics, ["strings", str(yara_path), "-o", str(strings_out), "-f", "text"])
    assert res.exit_code == 0
    assert strings_out.exists()
    assert "String analysis written to" in res.output


def test_metrics_graph_and_patterns_fallback_and_explicit_report_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = _write_metrics_rule(tmp_path)

    res = runner.invoke(
        metrics,
        ["graph", str(yara_path), "-t", "rules", "-f", "svg"],
    )
    assert res.exit_code == 0
    assert "Dependency graph generated" in res.output

    res = runner.invoke(
        metrics,
        ["patterns", str(yara_path), "-t", "flow", "-f", "svg", "--stats"],
    )
    assert res.exit_code == 0
    assert "Pattern diagram generated" in res.output

    output_dir = tmp_path / "explicit_report"
    res = runner.invoke(metrics, ["report", str(yara_path), "-d", str(output_dir), "-f", "svg"])
    assert res.exit_code == 0
    assert output_dir.exists()
    assert (output_dir / "summary.json").exists()


def test_optimize_error_path_with_invalid_utf8(tmp_path: Path) -> None:
    runner = CliRunner()
    input_file = tmp_path / "invalid.yar"
    output_file = tmp_path / "out.yar"
    input_file.write_bytes(b"\xff\xfe\xfa")

    result = runner.invoke(optimize, [str(input_file), str(output_file)])

    assert result.exit_code != 0
    assert "Error:" in result.output
    assert not output_file.exists()


def test_performance_reporting_small_remaining_branches(capsys, tmp_path: Path) -> None:
    pr.report_complexity_analysis([{"other": 1}], tmp_path)
    out = capsys.readouterr().out
    assert "Complexity analysis saved" in out
    assert "Average quality score" not in out

    pr._display_list_summary("Items", [], max_preview=5)
    assert capsys.readouterr().out == ""

    pr._display_list_summary("Items", ["a"], max_preview=5)
    out = capsys.readouterr().out
    assert "Items: 1" in out
    assert "    - a" in out

    plan_minimal = {
        "recommendations": {
            "batch_size": 1,
            "memory_limit_mb": 64,
            "enable_pooling": False,
            "use_streaming": True,
        },
        "collection_size": 1,
        "strategy": ["s"],
        "examples": {
            "batch": {"batch_size": 1, "memory_limit_mb": 64, "max_workers": 1},
            "stream": {"memory_limit_mb": 64},
        },
    }
    pr.display_optimize_report(plan_minimal)
    out = capsys.readouterr().out
    assert "Recommended Settings:" in out
    assert "Memory Planning" not in out
    assert "Time Optimization" not in out
