"""Scan handler for libyara commands."""

from __future__ import annotations

import click

from yaraast.cli.libyara_handlers_common import run_or_abort
from yaraast.cli.libyara_reporting import (
    display_compilation_errors,
    display_matches,
    display_optimization_hints,
    display_scan_failure,
    display_scan_stats,
    display_scan_summary,
)
from yaraast.cli.libyara_services import ensure_yara_available, scan_yara


def handle_scan(
    console,
    rules_file: str,
    target: str,
    optimize: bool,
    timeout: int | None,
    fast: bool,
    stats: bool,
) -> None:
    run_or_abort(ensure_yara_available, console)
    scan_result, matcher, compile_result = run_or_abort(
        scan_yara,
        console,
        rules_file,
        target,
        optimize,
        timeout,
        fast,
    )
    if scan_result is None:
        display_compilation_errors(console, compile_result.errors)
        raise click.Abort from None
    if scan_result["success"]:
        console.print("[green]Scan completed[/green]")
        matches = scan_result["matches"]
        display_scan_summary(console, scan_result, matches)
        display_matches(console, matches)
        display_optimization_hints(console, scan_result)
        if stats:
            display_scan_stats(console, matcher)
    else:
        display_scan_failure(console, scan_result)
        raise click.Abort from None
