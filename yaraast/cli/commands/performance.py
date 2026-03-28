"""CLI commands for performance optimization and large-scale processing."""

from __future__ import annotations

from pathlib import Path
import time

import click

from yaraast.cli.performance_reporting import (
    display_operation_result,
    display_optimize_report,
    display_parallel_summary,
    display_stream_details,
    display_stream_summary,
    report_complexity_analysis,
)
from yaraast.cli.performance_services import (
    build_batch_results_data,
    build_optimization_plan,
    build_parallel_summary,
    build_stream_output_data,
    collect_file_paths,
    convert_operations,
    get_parse_iterator,
    run_batch_processing,
    run_parallel_analysis,
)
from yaraast.cli.utils import write_json
from yaraast.performance import BatchProcessor, StreamingParser


@click.group()
def performance() -> None:
    """Performance tools for large YARA rule collections."""


@performance.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output-dir", "-o", type=click.Path(), help="Output directory")
@click.option(
    "--batch-size",
    "-b",
    type=int,
    default=50,
    help="Batch size for processing",
)
@click.option("--max-workers", "-w", type=int, help="Maximum worker threads")
@click.option("--memory-limit", "-m", type=int, default=1000, help="Memory limit in MB")
@click.option(
    "--operations",
    "-op",
    multiple=True,
    type=click.Choice(
        ["parse", "complexity", "dependency_graph", "html_tree", "serialize"],
    ),
    default=["parse", "complexity"],
    help="Operations to perform",
)
@click.option("--recursive", "-r", is_flag=True, help="Process directories recursively")
@click.option("--pattern", "-p", default="*.yar", help="File pattern to match")
@click.option("--progress", is_flag=True, help="Show progress information")
def batch(
    input_path: str,
    output_dir: str | None,
    batch_size: int,
    max_workers: int | None,
    memory_limit: int,
    operations: tuple,
    recursive: bool,
    pattern: str,
    progress: bool,
) -> None:
    """Process large collections of YARA files in batches."""
    input_path = Path(input_path)

    if not output_dir:
        output_dir = input_path.parent / f"{input_path.name}_batch_output"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    batch_operations = convert_operations(operations)

    # Progress callback
    def progress_callback(operation: str, current: int, total: int) -> None:
        if progress:
            percentage = (current / total * 100) if total > 0 else 0
            click.echo(
                f"\r{operation}: {current}/{total} ({percentage:.1f}%)",
                nl=False,
            )

    processor = BatchProcessor(
        max_workers=max_workers,
        max_memory_mb=memory_limit,
        batch_size=batch_size,
        progress_callback=progress_callback,
    )

    try:
        results, total_time = run_batch_processing(
            input_path,
            output_dir,
            batch_operations,
            processor,
            pattern,
            recursive,
        )

        if progress:
            click.echo()  # New line after progress

        click.echo(f"\n📊 Batch Processing Results ({total_time:.2f}s)")
        click.echo("=" * 50)

        for operation, result in results.items():
            display_operation_result(operation, result)

        results_file = output_dir / "batch_results.json"
        write_json(results_file, build_batch_results_data(results))
        click.echo(f"\n✅ Results saved to: {output_dir}")
    except Exception as e:
        click.echo(f"\n❌ Error during batch processing: {e}", err=True)
        raise click.Abort from None


@performance.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for parsing statistics",
)
@click.option("--memory-limit", "-m", type=int, default=500, help="Memory limit in MB")
@click.option("--pattern", "-p", default="*.yar", help="File pattern to match")
@click.option("--recursive", "-r", is_flag=True, help="Process directories recursively")
@click.option(
    "--split-rules",
    is_flag=True,
    help="Parse individual rules from large files",
)
@click.option("--progress", is_flag=True, help="Show progress information")
def stream(
    input_path: str,
    output: str | None,
    memory_limit: int,
    pattern: str,
    recursive: bool,
    split_rules: bool,
    progress: bool,
) -> None:
    """Stream-parse large YARA collections with minimal memory usage."""
    input_path = Path(input_path)

    # Progress callback
    def progress_callback(current: int, total: int, current_file: str) -> None:
        if progress:
            percentage = (current / total * 100) if total > 0 else 0
            file_name = Path(current_file).name
            click.echo(
                f"\r{current}/{total} ({percentage:.1f}%) - {file_name}",
                nl=False,
            )

    # Initialize streaming parser
    parser = StreamingParser(
        max_memory_mb=memory_limit,
        enable_gc=True,
        progress_callback=progress_callback,
    )

    results = []

    try:
        start_time = time.time()
        result_iter = get_parse_iterator(
            parser,
            input_path,
            split_rules,
            pattern,
            recursive,
        )

        # Process results
        for result in result_iter:
            results.append(result)

        total_time = time.time() - start_time

        if progress:
            click.echo()  # New line after progress

        _display_stream_results(results, total_time, parser, output)

    except KeyboardInterrupt:
        parser.cancel()
        click.echo("\n⏹️  Parsing cancelled by user")
    except Exception as e:
        click.echo(f"\n❌ Error during streaming parse: {e}", err=True)
        raise click.Abort from None


def _display_stream_results(
    results: list,
    total_time: float,
    parser: StreamingParser,
    output: str | None,
) -> None:
    """Display streaming parse statistics and optionally save results to file."""
    successful, failed = display_stream_summary(results, total_time)

    parser_stats = parser.get_statistics()
    display_stream_details(successful, failed, parser_stats)

    if output:
        output_data = build_stream_output_data(
            results,
            successful,
            failed,
            total_time,
            parser_stats,
        )
        write_json(output, output_data)
        click.echo(f"\n📁 Detailed results saved to: {output}")


@performance.command()
@click.argument("input_paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--output-dir", "-o", type=click.Path(), help="Output directory")
@click.option("--max-workers", "-w", type=int, help="Maximum worker threads")
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=300.0,
    help="Job timeout in seconds",
)
@click.option(
    "--analysis-type",
    "-a",
    type=click.Choice(["complexity", "dependency", "all"]),
    default="complexity",
    help="Type of analysis to perform",
)
@click.option(
    "--chunk-size",
    "-c",
    type=int,
    default=10,
    help="Files per processing chunk",
)
def parallel(
    input_paths: tuple,
    output_dir: str | None,
    max_workers: int | None,
    timeout: float,
    analysis_type: str,
    chunk_size: int,
) -> None:
    """Analyze YARA files in parallel using thread pooling."""
    file_paths = collect_file_paths(input_paths)

    if not file_paths:
        click.echo("❌ No YARA files found to process")
        return

    if not output_dir:
        output_dir = Path.cwd() / "parallel_analysis_output"
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    click.echo(f"🚀 Starting parallel analysis of {len(file_paths)} files...")
    click.echo(f"   Max workers: {max_workers or 'auto'}")
    click.echo(f"   Chunk size: {chunk_size}")
    click.echo(f"   Analysis type: {analysis_type}")

    try:
        click.echo("\n📋 Parsing files...")
        run_results, total_time = run_parallel_analysis(
            file_paths,
            max_workers,
            chunk_size,
            analysis_type,
            output_dir,
        )

        successful_asts = run_results["successful_asts"]
        run_results["file_names"]
        complexity_results = run_results["complexity_results"]
        dependency_graphs = run_results["dependency_graphs"]
        analyzer_stats = run_results["analyzer_stats"]

        click.echo(f"✅ Successfully parsed {len(successful_asts)} files")

        if not successful_asts:
            click.echo("❌ No files parsed successfully")
            return

        report_complexity_analysis(complexity_results, output_dir)

        if dependency_graphs:
            click.echo(f"📈 Generated {len(dependency_graphs)} dependency graphs")

        summary = build_parallel_summary(
            file_paths,
            successful_asts,
            analyzer_stats,
            total_time,
        )
        display_parallel_summary(summary, total_time)

    except KeyboardInterrupt:
        click.echo("\n⏹️  Analysis cancelled by user")
    except Exception as e:
        click.echo(f"\n❌ Error during parallel analysis: {e}", err=True)
        raise click.Abort from None


@performance.command()
@click.argument("collection_size", type=int)
@click.option("--memory-mb", type=int, help="Available memory in MB")
@click.option("--target-time", type=int, help="Target processing time in seconds")
def optimize(collection_size: int, memory_mb: int | None, target_time: int | None) -> None:
    """Get optimization recommendations for processing large collections."""
    plan = build_optimization_plan(collection_size, memory_mb, target_time)
    display_optimize_report(plan)
