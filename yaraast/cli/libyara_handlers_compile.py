"""Compile handler for libyara commands."""

from __future__ import annotations

import click

from yaraast.cli.libyara_handlers_common import run_or_abort
from yaraast.cli.libyara_reporting import (
    display_compilation_errors,
    display_compilation_stats,
    display_compilation_success,
    display_compiled_rules_saved,
    display_generated_source_preview,
    display_optimization_stats,
)
from yaraast.cli.libyara_services import compile_yara, ensure_yara_available


def handle_compile(
    console, input_file: str, output: str | None, optimize: bool, debug: bool, stats: bool
) -> None:
    run_or_abort(ensure_yara_available, console)
    result, compiler, _ast = run_or_abort(compile_yara, console, input_file, optimize, debug)

    if not result.success:
        display_compilation_errors(console, result.errors)
        raise click.Abort from None

    display_compilation_success(console)

    if result.optimized:
        display_optimization_stats(console, result)

    if stats:
        display_compilation_stats(console, result, compiler)

    if output and result.compiled_rules:
        result.compiled_rules.save(output)
        display_compiled_rules_saved(console, output)

    if debug and result.generated_source:
        display_generated_source_preview(console, result.generated_source)
