"""Real CLI tests for performance commands (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import signal
import stat
import sys
from textwrap import dedent
import threading
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

import yaraast.cli.commands.performance as performance_command
from yaraast.cli.commands.performance import performance


def _write(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content), encoding="utf-8")
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


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


def test_performance_batch_file(tmp_path: Path) -> None:
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
    payload = json.loads(results_file.read_text(encoding="utf-8"))
    assert "parse" in payload


def test_performance_batch_rejects_zero_batch_size(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "batch",
            file_path,
            "--batch-size",
            "0",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--batch-size'" in result.output


def test_performance_batch_rejects_zero_max_workers(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "batch",
            file_path,
            "--max-workers",
            "0",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--max-workers'" in result.output


def test_performance_batch_rejects_zero_memory_limit(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "batch",
            file_path,
            "--memory-limit",
            "0",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--memory-limit'" in result.output


def test_performance_batch_file_serialize_outputs_result(tmp_path: Path) -> None:
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
            "serialize",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads((out_dir / "batch_results.json").read_text(encoding="utf-8"))
    assert payload["serialize"]["successful_count"] == 1
    assert payload["serialize"]["output_files"]
    assert Path(payload["serialize"]["output_files"][0]).exists()


def test_performance_batch_file_validate_outputs_result(tmp_path: Path) -> None:
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
            "validate",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads((out_dir / "batch_results.json").read_text(encoding="utf-8"))
    validation_result = payload["validate"]
    assert validation_result["successful_count"] == 1
    assert validation_result["failed_count"] == 0
    assert validation_result["summary"] == {"rule_count": 1, "valid": True}


def test_performance_batch_file_with_split_rules_counts_rules(tmp_path: Path) -> None:
    file_path = _write(
        tmp_path,
        "rules.yar",
        """
        rule first {
            condition:
                true
        }

        rule second {
            condition:
                true
        }
        """,
    )
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
            "--split-rules",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads((out_dir / "batch_results.json").read_text(encoding="utf-8"))
    assert payload["parse"]["input_count"] == 2
    assert payload["parse"]["successful_count"] == 2


def test_performance_batch_file_dependency_graph_outputs_result(tmp_path: Path) -> None:
    file_path = _write(
        tmp_path,
        "rule.yar",
        """
        rule first {
            condition:
                second
        }

        rule second {
            condition:
                true
        }
        """,
    )
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
            "dependency_graph",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads((out_dir / "batch_results.json").read_text(encoding="utf-8"))
    graph_result = payload["dependency_graph"]
    assert graph_result["successful_count"] == 1
    assert len(graph_result["output_files"]) == 2
    assert Path(graph_result["output_files"][0]).exists()


def test_performance_stream_file(tmp_path: Path) -> None:
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
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["summary"]["total_processed"] >= 1


def test_performance_stream_rejects_empty_output_path(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "stream",
            file_path,
            "--output",
            "",
        ],
    )

    assert result.exit_code != 0
    assert "path must not be empty" in result.output
    assert "Streaming Parse Results" not in result.output


def test_performance_output_dir_commands_reject_empty_path(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        for command in ("batch", "parallel"):
            result = runner.invoke(
                performance,
                [
                    command,
                    file_path,
                    "--output-dir",
                    "",
                ],
            )

            assert result.exit_code == 2
            assert "path must not be empty" in result.output

        assert not Path("parallel_analysis_output").exists()

    assert not (tmp_path / "rule.yar_batch_output").exists()


def test_performance_batch_rejects_default_output_dir_under_symlinked_parent(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(outside, target_is_directory=True)
    input_file = link_dir / "rule.yar"
    input_file.write_text(dedent(_sample_yara()).strip() + "\n", encoding="utf-8")

    result = CliRunner().invoke(performance, ["batch", str(input_file), "--operations", "parse"])

    assert result.exit_code == 2
    assert "output path must not traverse a symlink" in result.output
    assert not (outside / "rule.yar_batch_output").exists()


def test_performance_stream_rejects_zero_memory_limit(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "stream",
            file_path,
            "--memory-limit",
            "0",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--memory-limit'" in result.output


def test_performance_parallel_and_optimize(tmp_path: Path) -> None:
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


def test_performance_optimize_rejects_invalid_numeric_options() -> None:
    runner = CliRunner()

    collection = runner.invoke(performance, ["optimize", "--", "-1"])
    assert collection.exit_code == 2
    assert "Invalid value for 'COLLECTION_SIZE'" in collection.output

    memory = runner.invoke(performance, ["optimize", "1", "--memory-mb", "0"])
    assert memory.exit_code == 2
    assert "Invalid value for '--memory-mb'" in memory.output

    target = runner.invoke(performance, ["optimize", "1", "--target-time", "0"])
    assert target.exit_code == 2
    assert "Invalid value for '--target-time'" in target.output


def test_performance_parallel_rejects_zero_chunk_size(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "parallel",
            file_path,
            "--chunk-size",
            "0",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--chunk-size'" in result.output


def test_performance_parallel_rejects_zero_max_workers(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "parallel",
            file_path,
            "--max-workers",
            "0",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--max-workers'" in result.output


def test_performance_parallel_rejects_zero_timeout(tmp_path: Path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    result = CliRunner().invoke(
        performance,
        [
            "parallel",
            file_path,
            "--timeout",
            "0",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--timeout'" in result.output


def test_performance_batch_uses_default_output_dir_and_progress(tmp_path: Path) -> None:
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


def test_performance_batch_directory_without_progress_covers_silent_callback(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "one.yar", _sample_yara())
    _write(tmp_path, "two.yara", _sample_yara().replace("perf_rule", "silent_rule"))
    _write(tmp_path, "native.yarax", _sample_yara().replace("perf_rule", "native_rule"))
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
    payload = json.loads((out_dir / "batch_results.json").read_text(encoding="utf-8"))
    assert payload["parse"]["input_count"] == 2


def test_performance_stream_progress_without_output_file(tmp_path: Path) -> None:
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


def test_performance_parallel_empty_directory_and_failed_parse(tmp_path: Path) -> None:
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


def test_performance_parallel_dependency_and_default_output_dir(tmp_path: Path) -> None:
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


def test_performance_parallel_creates_nested_output_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    output_dir = tmp_path / "nested" / "parallel"

    result = runner.invoke(
        performance,
        [
            "parallel",
            file_path,
            "--output-dir",
            str(output_dir),
            "--analysis-type",
            "complexity",
            "--chunk-size",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "complexity_analysis.json").exists()


@pytest.mark.parametrize(
    ("command_factory", "service_name", "message"),
    [
        (
            lambda rule_path, output_path: [
                "batch",
                rule_path,
                "--output-dir",
                output_path,
                "--operations",
                "parse",
            ],
            "run_batch_processing",
            "Error during batch processing",
        ),
        (
            lambda rule_path, _output_path: ["stream", rule_path],
            "get_parse_iterator",
            "Error during streaming parse",
        ),
        (
            lambda rule_path, _output_path: ["parallel", rule_path],
            "collect_file_paths",
            "Error during parallel analysis",
        ),
    ],
)
def test_performance_commands_abort_preserves_original_cause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_factory: Callable[[str, str], list[str]],
    service_name: str,
    message: str,
) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    output_path = str(tmp_path / "out")
    sentinel = RuntimeError("performance sentinel")

    def fail_service(*_args: object, **_kwargs: object) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(performance_command, service_name, fail_service)

    result = CliRunner().invoke(
        performance,
        command_factory(file_path, output_path),
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert message in result.output
    assert "performance sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)


@pytest.mark.skipif(sys.platform == "win32", reason="chmod read-only not effective on Windows")
def test_performance_batch_and_stream_abort_on_real_write_errors(tmp_path: Path) -> None:
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
def test_performance_parallel_abort_on_real_complexity_write_error(tmp_path: Path) -> None:
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
def test_performance_stream_and_parallel_handle_real_sigint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    def interrupt_parallel_analysis(*args: object, **kwargs: object) -> None:
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(
        "yaraast.cli.commands.performance.run_parallel_analysis",
        interrupt_parallel_analysis,
    )
    parallel = CliRunner().invoke(
        performance,
        ["parallel", str(rules_dir), "--analysis-type", "complexity", "--chunk-size", "1"],
    )
    assert parallel.exit_code == 0
    assert "Analysis cancelled by user" in parallel.output
