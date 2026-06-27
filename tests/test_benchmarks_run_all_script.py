from __future__ import annotations

from pathlib import Path
import random
import subprocess
import sys

import pytest

from benchmarks.test_file_generator import YaraTestFileGenerator
from yaraast.parser import Parser

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


def test_benchmark_generator_emits_parseable_regex_literals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(random, "choice", lambda _patterns: r"\w+@\w+\.\w+")
    monkeypatch.setattr(random, "random", lambda: 0.99)

    regex = YaraTestFileGenerator(seed=1).generate_regex_string()

    assert regex == r"/\w+@\w+\.\w+/is"


def test_benchmark_generator_escapes_forward_slashes_in_regex_patterns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(random, "choice", lambda _patterns: r"https?:\/\/[^\s]+")
    monkeypatch.setattr(random, "random", lambda: 0.0)

    regex = YaraTestFileGenerator(seed=1).generate_regex_string()

    assert regex == r"/https?:\/\/[^\s]+/"


def test_benchmark_generator_emits_parseable_hex_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    random_values = iter([0.1] * 8 + [0.9])

    def fake_random() -> float:
        return next(random_values)

    def fake_randint(low: int, high: int) -> int:
        if (low, high) == (4, 20):
            return 4
        if (low, high) == (0, 255):
            return 0x4D
        if (low, high) == (1, 10):
            return 2
        return low

    monkeypatch.setattr(random, "random", fake_random)
    monkeypatch.setattr(random, "randint", fake_randint)
    monkeypatch.setattr(random, "choice", lambda _choices: _choices[0])

    hex_string = YaraTestFileGenerator(seed=1).generate_hex_string()
    ast = Parser().parse(
        f"""
        rule hex_test {{
            strings:
                $h = {hex_string}
            condition:
                $h
        }}
        """.strip(),
    )

    assert ast is not None
    assert ast.rules[0].name == "hex_test"
