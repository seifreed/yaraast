from __future__ import annotations

from pathlib import Path
import subprocess
import sys

BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "benchmarks"
SCRIPT_PATH = BENCHMARK_DIR / "run_all_benchmarks.py"


def test_run_all_benchmarks_help_skips_dependency_checks() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
    )

    assert proc.returncode == 0
    assert "Run the complete YARA AST parser benchmark suite" in proc.stdout
    assert "Missing required dependencies" not in proc.stdout


def test_benchmark_entrypoint_help_does_not_run_workloads(tmp_path: Path) -> None:
    scripts = (
        "benchmark_large_files.py",
        "memory_profiler.py",
        "profiler.py",
        "test_file_generator.py",
    )

    for script in scripts:
        proc = subprocess.run(
            [sys.executable, str(BENCHMARK_DIR / script), "--help"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
        )

        assert proc.returncode == 0, script
        assert "usage:" in proc.stdout
        assert not (tmp_path / "test_data").exists()
        assert not (tmp_path / "results").exists()
