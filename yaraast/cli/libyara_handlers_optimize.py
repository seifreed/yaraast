"""Optimize handler for libyara commands."""

from __future__ import annotations

from yaraast.cli.libyara_handlers_common import run_or_abort
from yaraast.cli.libyara_reporting import display_optimize_results
from yaraast.cli.libyara_services import ensure_yara_available, optimize_yara


def handle_optimize(console, input_file: str, show_optimizations: bool) -> None:
    run_or_abort(ensure_yara_available, console)
    optimizer, optimized_code = run_or_abort(optimize_yara, console, input_file)
    display_optimize_results(console, optimizer, show_optimizations, optimized_code)
