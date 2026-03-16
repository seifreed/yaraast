"""CLI command for performance benchmarks of AST operations."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from yaraast.cli.bench_reporting import (
    display_benchmark_file,
    display_benchmark_summary,
    display_operation_result,
    display_performance_comparison,
    print_benchmark_header,
    save_benchmark_results,
)
from yaraast.cli.bench_services import (
    _determine_operations_to_run,
    _get_benchmark_summary,
    _run_single_operation,
)

console = Console()


@click.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True), required=True)
@click.option(
    "--operations",
    type=click.Choice(["parse", "codegen", "roundtrip", "all"]),
    default="all",
    help="Operations to benchmark",
)
@click.option(
    "--iterations",
    type=int,
    default=10,
    help="Number of iterations per test",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output benchmark results to JSON file",
)
@click.option("--compare", is_flag=True, help="Compare performance across files")
def bench(
    files: tuple[str],
    operations: str,
    iterations: int,
    output: str | None,
    compare: bool,
) -> None:
    """Performance benchmarks for AST operations."""
    try:
        from yaraast.cli.ast_tools import ASTBenchmarker

        file_paths = [Path(f) for f in files]
        benchmarker = ASTBenchmarker()

        print_benchmark_header(file_paths, iterations)
        all_results = []
        ops_to_run = _determine_operations_to_run(operations)
        for file_path in file_paths:
            display_benchmark_file(file_path)
            file_results = {}
            for op in ops_to_run:
                result = _run_single_operation(benchmarker, file_path, op, iterations)
                if result:
                    display_operation_result(op, result)
                    if result.success:
                        file_results[op] = result

            all_results.append(
                {
                    "file": str(file_path),
                    "file_name": file_path.name,
                    "results": file_results,
                }
            )
        summary = _get_benchmark_summary(benchmarker)
        display_benchmark_summary(summary)

        if compare and len(file_paths) > 1:
            display_performance_comparison(all_results)

        if output:
            save_benchmark_results(output, iterations, operations, all_results, summary)

        console.print("\nBenchmarking completed!")

    except Exception as e:
        from rich.markup import escape

        console.print(f"[red]Error: {escape(str(e))}[/red]")
        raise click.Abort from None
