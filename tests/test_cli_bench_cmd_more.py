from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

from yaraast.cli.benchmark_tools import ASTBenchmarker, BenchmarkResult
import yaraast.cli.commands.bench_cmd as bench_command
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
""".strip(),
        encoding="utf-8",
    )


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


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
    data = json.loads(output.read_text(encoding="utf-8"))
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


def test_bench_command_rejects_empty_output_path(tmp_path: Path) -> None:
    runner = CliRunner()
    file_a = tmp_path / "a.yar"
    _write_rule(file_a, "a")

    result = runner.invoke(
        bench,
        [str(file_a), "--iterations", "1", "--output", ""],
    )

    assert result.exit_code != 0
    assert "path must not be empty" in result.output
    assert "Benchmarking" not in result.output


def test_bench_command_rejects_zero_iterations(tmp_path: Path) -> None:
    runner = CliRunner()
    file_a = tmp_path / "a.yar"
    _write_rule(file_a, "a")

    result = runner.invoke(bench, [str(file_a), "--iterations", "0"])

    assert result.exit_code == 2
    assert "Invalid value for '--iterations'" in result.output


def test_bench_command_rejects_non_positive_file_timeout(tmp_path: Path) -> None:
    runner = CliRunner()
    file_a = tmp_path / "a.yar"
    _write_rule(file_a, "a")

    result = runner.invoke(bench, [str(file_a), "--iterations", "1", "--file-timeout", "0"])

    assert result.exit_code == 2
    assert "Invalid value for '--file-timeout'" in result.output


def test_bench_command_passes_file_timeout_to_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()
    file_a = tmp_path / "a.yar"
    _write_rule(file_a, "a")
    seen: dict[str, float | None] = {}

    def fake_run_single_operation(
        _benchmarker: ASTBenchmarker,
        _file_path: Path,
        op: str,
        _iterations: int,
        file_timeout: float | None,
    ) -> BenchmarkResult:
        seen[op] = file_timeout
        result = BenchmarkResult(
            operation=op,
            file_size=0,
            execution_time=0.001,
            rules_count=1,
            strings_count=0,
            ast_nodes=2,
            success=True,
        )
        _benchmarker.results.append(result)
        return result

    monkeypatch.setattr(bench_command, "_run_single_operation", fake_run_single_operation)

    result = runner.invoke(
        bench,
        [str(file_a), "--iterations", "1", "--file-timeout", "0.5", "--operations", "parse"],
    )

    assert result.exit_code == 0
    assert seen["parse"] == 0.5


def test_bench_command_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_a = tmp_path / "a.yar"
    _write_rule(file_a, "a")
    sentinel = RuntimeError("bench sentinel")

    def fail_determine_operations(_operations: str) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(bench_command, "_determine_operations_to_run", fail_determine_operations)

    result = CliRunner().invoke(
        bench,
        [str(file_a), "--iterations", "1"],
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert "bench sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)
