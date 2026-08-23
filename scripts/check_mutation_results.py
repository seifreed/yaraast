#!/usr/bin/env python3
"""Enforce a minimum mutmut score and reject incomplete mutation runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

_INCOMPLETE_STATES = (
    "no_tests",
    "suspicious",
    "timeout",
    "segfault",
    "check_was_interrupted_by_user",
)


def check_results(stats: dict[str, int], minimum_score: float) -> tuple[bool, float]:
    total = stats.get("total", 0)
    score = 100.0 * stats.get("killed", 0) / total if total else 0.0
    complete = total > 0 and not any(stats.get(state, 0) for state in _INCOMPLETE_STATES)
    return complete and score >= minimum_score, score


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stats_path", type=Path)
    parser.add_argument("--minimum-score", type=float, default=75.0)
    args = parser.parse_args()
    stats = json.loads(args.stats_path.read_text(encoding="utf-8"))
    ok, score = check_results(stats, args.minimum_score)
    print(f"Mutation score: {score:.2f}% (minimum: {args.minimum_score:.2f}%)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
