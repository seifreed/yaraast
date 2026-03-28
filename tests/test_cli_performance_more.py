"""Real CLI tests for performance commands (no mocks)."""

from __future__ import annotations

import json
import os
import signal
import stat
import sys
import threading
from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from yaraast.cli.commands.performance import performance


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def _sample_yara() -> str:
    return """
    rule perf_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """


def test_performance_batch_file(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    out_dir = tmp_path / "batch_out"
    runner = CliRunner()

    result = runner.invoke(
        performance,
        [
            "batch",
            file_path,
            "--output-dir",
            str(out_dir),
            "--operations",
            "parse",
        ],
    )

    assert result.exit_code == 0
    assert out_dir.exists()
    results_file = out_dir / "batch_results.json"
    assert results_file.exists()
    payload = json.loads(results_file.read_text())
    assert "parse" in payload


def test_performance_stream_file(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    out_file = tmp_path / "stream_results.json"
    runner = CliRunner()

    result = runner.invoke(
        performance,
        [
            "stream",
            file_path,
            "--output",
            str(out_file),
        ],
    )

    assert result.exit_code == 0
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["summary"]["total_processed"] >= 1


def test_performance_parallel_and_optimize(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    out_dir = tmp_path / "parallel_out"
    runner = CliRunner()

    parallel = runner.invoke(
        performance,
        [
            "parallel",
            file_path,
            "--output-dir",
            str(out_dir),
            "--analysis-type",
            "complexity",
            "--chunk-size",
            "1",
        ],
    )

    assert parallel.exit_code == 0
    assert out_dir.exists()
    assert (out_dir / "complexity_analysis.json").exists()

    optimize = runner.invoke(
        performance,
        ["optimize", "10", "--memory-mb", "256", "--target-time", "5"],
    )

    assert optimize.exit_code == 0
    assert "Optimization Recommendations" in optimize.output


def test_performance_batch_uses_default_output_dir_and_progress(tmp_path) -> None:
    first = _write(tmp_path, "one.yar", _sample_yara())
    _write(tmp_path, "two.yar", _sample_yara().replace("perf_rule", "perf_rule_two"))
    runner = CliRunner()

    result = runner.invoke(
        performance,
        [
            "batch",
            str(tmp_path),
            "--operations",
            "parse",
            "--recursive",
            "--progress",
        ],
    )

    assert result.exit_code == 0
    assert "%" in result.output
    assert (tmp_path.parent / f"{tmp_path.name}_batch_output" / "batch_results.json").exists()
    assert first


def test_performance_batch_directory_without_progress_covers_silent_callback(tmp_path) -> None:
    _write(tmp_path, "one.yar", _sample_yara())
    _write(tmp_path, "two.yar", _sample_yara().replace("perf_rule", "silent_rule"))
    runner = CliRunner()
    out_dir = tmp_path / "silent_out"

    result = runner.invoke(
        performance,
        [
            "batch",
            str(tmp_path),
            "--output-dir",
            str(out_dir),
            "--operations",
            "parse",
            "--recursive",
        ],
    )

    assert result.exit_code == 0
    assert (out_dir / "batch_results.json").exists()


def test_performance_stream_progress_without_output_file(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    runner = CliRunner()

    result = runner.invoke(
        performance,
        [
            "stream",
            file_path,
            "--progress",
        ],
    )

    assert result.exit_code == 0
    assert "%" in result.output
    assert "rule.yar" in result.output


def test_performance_parallel_empty_directory_and_failed_parse(tmp_path) -> None:
    runner = CliRunner()
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    result = runner.invoke(performance, ["parallel", str(empty_dir)])
    assert result.exit_code == 0
    assert "No YARA files found to process" in result.output

    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    (bad_dir / "broken.yar").write_text("rule broken { condition: ", encoding="utf-8")
    result = runner.invoke(
        performance, ["parallel", str(bad_dir), "--output-dir", str(tmp_path / "bad_out")]
    )
    assert result.exit_code == 0
    assert "No files parsed successfully" in result.output


def test_performance_parallel_dependency_and_default_output_dir(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        rule_path = Path("rule.yar")
        rule_path.write_text(dedent(_sample_yara()).strip() + "\n", encoding="utf-8")

        result = runner.invoke(
            performance,
            [
                "parallel",
                str(rule_path),
                "--analysis-type",
                "dependency",
                "--chunk-size",
                "1",
            ],
        )

        assert result.exit_code == 0
        assert "Generated 1 dependency graphs" in result.output
        assert Path("parallel_analysis_output").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="chmod read-only not effective on Windows")
def test_performance_batch_and_stream_abort_on_real_write_errors(tmp_path) -> None:
    runner = CliRunner()
    file_path = _write(tmp_path, "rule.yar", _sample_yara())

    ro_dir = tmp_path / "readonly_batch"
    ro_dir.mkdir()
    ro_dir.chmod(stat.S_IREAD | stat.S_IEXEC)
    try:
        batch = runner.invoke(
            performance,
            [
                "batch",
                file_path,
                "--output-dir",
                str(ro_dir),
                "--operations",
                "parse",
            ],
        )
    finally:
        ro_dir.chmod(stat.S_IRWXU)

    assert batch.exit_code == 1
    assert "Error during batch processing" in batch.output

    stream = runner.invoke(
        performance,
        [
            "stream",
            file_path,
            "--output",
            str(tmp_path / "missing" / "stream.json"),
        ],
    )
    assert stream.exit_code == 1
    assert "Error during streaming parse" in stream.output


@pytest.mark.skipif(sys.platform == "win32", reason="chmod read-only not effective on Windows")
def test_performance_parallel_abort_on_real_complexity_write_error(tmp_path) -> None:
    runner = CliRunner()
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    ro_dir = tmp_path / "readonly_parallel"
    ro_dir.mkdir()
    ro_dir.chmod(stat.S_IREAD | stat.S_IEXEC)
    try:
        result = runner.invoke(
            performance,
            [
                "parallel",
                file_path,
                "--output-dir",
                str(ro_dir),
                "--analysis-type",
                "complexity",
                "--chunk-size",
                "1",
            ],
        )
    finally:
        ro_dir.chmod(stat.S_IRWXU)

    assert result.exit_code == 1
    assert "Error during parallel analysis" in result.output


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT via os.kill not reliable on Windows")
def test_performance_stream_and_parallel_handle_real_sigint(tmp_path) -> None:
    rules_dir = tmp_path / "sigint_rules"
    rules_dir.mkdir()
    for i in range(2000):
        (rules_dir / f"{i}.yar").write_text(dedent(_sample_yara()).strip() + "\n", encoding="utf-8")

    timer = threading.Timer(0.3, lambda: os.kill(os.getpid(), signal.SIGINT))
    timer.start()
    try:
        stream = CliRunner().invoke(
            performance,
            ["stream", str(rules_dir), "--recursive", "--progress"],
        )
    finally:
        timer.cancel()
    assert stream.exit_code == 0
    assert "Parsing cancelled by user" in stream.output

    timer = threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGINT))
    timer.start()
    try:
        parallel = CliRunner().invoke(
            performance,
            ["parallel", str(rules_dir), "--analysis-type", "complexity", "--chunk-size", "1"],
        )
    finally:
        timer.cancel()
    assert parallel.exit_code == 0
    assert "Analysis cancelled by user" in parallel.output
