"""Reporting helpers for benchmark CLI output."""

from __future__ import annotations

from pathlib import Path
import time

from rich.console import Console

from yaraast.cli.utils import format_json, write_text

console = Console()


def print_benchmark_header(file_paths: list[Path], iterations: int) -> None:
    """Print benchmark header information."""
    console.print("[blue]Running AST Performance Benchmarks[/blue]")
    console.print(f"Files: {len(file_paths)}, Iterations: {iterations}")
    console.print("=" * 60)


def display_benchmark_file(file_path: Path) -> None:
    """Display file heading for benchmark run."""
    console.print(f"\n[yellow]Benchmarking {file_path.name}...[/yellow]")


def display_operation_result(op: str, result) -> None:
    """Display result of a single operation."""
    if result and result.success:
        console.print(
            f"  [green]OK[/green] {op:10s}: {result.execution_time * 1000:6.2f}ms "
            f"({result.rules_count} rules, {result.ast_nodes} nodes)",
        )
    elif result:
        console.print(f"  [red]FAIL[/red] {op:10s}: {result.error}")


def display_benchmark_summary(summary: dict) -> None:
    """Display benchmark summary."""
    console.print("\n[green]Benchmark Summary:[/green]")
    console.print("=" * 60)

    for operation, stats in summary.items():
        console.print(f"\n[bold]{operation.upper()}:[/bold]")
        console.print(f"  - Average time: {stats['avg_time'] * 1000:.2f}ms")
        console.print(f"  - Min time: {stats['min_time'] * 1000:.2f}ms")
        console.print(f"  - Max time: {stats['max_time'] * 1000:.2f}ms")
        console.print(f"  - Files processed: {stats['total_files_processed']}")
        console.print(f"  - Rules processed: {stats['total_rules_processed']}")
        console.print(f"  - Rules/second: {stats['avg_rules_per_second']:.1f}")


def display_performance_comparison(all_results: list[dict]) -> None:
    """Display performance comparison between files."""
    console.print("\n[blue]Performance Comparison:[/blue]")
    console.print("=" * 60)

    parse_results = [
        (r["file_name"], r["results"].get("parse")) for r in all_results if "parse" in r["results"]
    ]

    if parse_results:
        _display_parsing_comparison(parse_results)


def _display_parsing_comparison(parse_results: list[tuple]) -> None:
    """Display parsing performance comparison."""
    parse_results.sort(
        key=lambda x: x[1].execution_time if x[1] else float("inf"),
    )
    console.print("\n[yellow]Parsing Performance (fastest to slowest):[/yellow]")

    for i, (filename, result) in enumerate(parse_results):
        if result:
            throughput = (
                result.rules_count / result.execution_time if result.execution_time > 0 else 0
            )
            console.print(
                f"  {i + 1:2d}. {filename:20s} "
                f"{result.execution_time * 1000:6.2f}ms "
                f"({throughput:.1f} rules/sec)",
            )


def save_benchmark_results(
    output: str,
    iterations: int,
    operations: str,
    all_results: list[dict],
    summary: dict,
) -> None:
    """Save benchmark results to JSON file."""
    benchmark_data = {
        "timestamp": time.time(),
        "iterations": iterations,
        "operations": operations,
        "files": all_results,
        "summary": summary,
    }

    write_text(output, format_json(benchmark_data, default=str))

    console.print(f"\n[green]Benchmark results saved to {output}[/green]")
