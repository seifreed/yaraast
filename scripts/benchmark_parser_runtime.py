#!/usr/bin/env python3
"""Gate parser and generator runtime against explicit regression limits."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from math import ceil
from pathlib import Path
from statistics import median
import tempfile

from yaraast.cli.benchmark_tools import ASTBenchmarker, BenchmarkResult


def _make_source(rule_count: int) -> str:
    return "\n".join(
        f'rule benchmark_{index} {{ strings: $a = "value-{index}" condition: $a }}'
        for index in range(rule_count)
    )


def _operation_report(results: list[BenchmarkResult], max_seconds: float) -> dict[str, object]:
    durations = [result.execution_time for result in results]
    representative = results[0]
    p95_index = max(0, ceil(len(durations) * 0.95) - 1)
    ordered_durations = sorted(durations)
    p95_seconds = ordered_durations[p95_index]
    return {
        **asdict(representative),
        "samples": len(results),
        "sample_times": durations,
        "median_seconds": median(durations),
        "p95_seconds": p95_seconds,
        "max_seconds": max_seconds,
        "rules_per_second": (
            representative.rules_count / median(durations) if median(durations) > 0 else 0.0
        ),
        "ok": all(result.success for result in results) and p95_seconds <= max_seconds,
    }


def run_regression_suite(
    rule_count: int = 1_000,
    iterations: int = 3,
    parsing_max_seconds: float = 3.0,
    codegen_max_seconds: float = 3.0,
    roundtrip_max_seconds: float = 6.0,
    samples: int = 3,
) -> dict[str, object]:
    if samples < 1:
        raise ValueError("samples must be positive")
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "benchmark.yar"
        input_path.write_text(_make_source(rule_count), encoding="utf-8")
        parsing = _operation_report(
            [ASTBenchmarker().benchmark_parsing(input_path, iterations) for _ in range(samples)],
            parsing_max_seconds,
        )
        codegen = _operation_report(
            [ASTBenchmarker().benchmark_codegen(input_path, iterations) for _ in range(samples)],
            codegen_max_seconds,
        )
        roundtrip = _operation_report(
            [
                ASTBenchmarker().benchmark_roundtrip(input_path, iterations)[0]
                for _ in range(samples)
            ],
            roundtrip_max_seconds,
        )
        operations = {"parsing": parsing, "codegen": codegen, "roundtrip": roundtrip}
        return {
            "input": {"rules": rule_count, "bytes": input_path.stat().st_size},
            "iterations": iterations,
            "samples": samples,
            "operations": operations,
            "ok": all(bool(report["ok"]) for report in operations.values()),
        }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_path", type=Path)
    parser.add_argument("--rules", type=int, default=1_000)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--parsing-max-seconds", type=float, default=3.0)
    parser.add_argument("--codegen-max-seconds", type=float, default=3.0)
    parser.add_argument("--roundtrip-max-seconds", type=float, default=6.0)
    parser.add_argument("--samples", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    report = run_regression_suite(
        rule_count=args.rules,
        iterations=args.iterations,
        parsing_max_seconds=args.parsing_max_seconds,
        codegen_max_seconds=args.codegen_max_seconds,
        roundtrip_max_seconds=args.roundtrip_max_seconds,
        samples=args.samples,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output_path.parent.mkdir(parents=True, exist_ok=True)
    args.output_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
