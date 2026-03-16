from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.bench_cmd import bench


def _write_rule(path: Path, name: str) -> None:
    path.write_text(
        f"""
rule {name} {{
    strings:
        $a = "test"
    condition:
        $a
}}
""".strip()
    )


def test_bench_command_compare_multiple_files_and_output_json(tmp_path: Path) -> None:
    runner = CliRunner()
    file_a = tmp_path / "a.yar"
    file_b = tmp_path / "b.yar"
    output = tmp_path / "bench.json"
    _write_rule(file_a, "a")
    _write_rule(file_b, "b")

    result = runner.invoke(
        bench,
        [str(file_a), str(file_b), "--iterations", "1", "--compare", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert "Performance Comparison" in result.output
    assert "Benchmarking completed!" in result.output
    data = json.loads(output.read_text())
    assert len(data["files"]) == 2


def test_bench_command_aborts_on_output_write_error(tmp_path: Path) -> None:
    runner = CliRunner()
    file_a = tmp_path / "a.yar"
    bad_output = tmp_path / "as_dir"
    _write_rule(file_a, "a")
    bad_output.mkdir()

    result = runner.invoke(
        bench,
        [str(file_a), "--iterations", "1", "--output", str(bad_output)],
    )

    assert result.exit_code != 0
    assert "Error:" in result.output
