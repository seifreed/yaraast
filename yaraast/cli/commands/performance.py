"""CLI commands for performance optimization and large-scale processing."""

import json
import time
from pathlib import Path

import click

from yaraast.performance import (
    BatchOperation,
    BatchProcessor,
    MemoryOptimizer,
    ParallelAnalyzer,
    StreamingParser,
)


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
def _convert_operations(operations):
    """Convert operation strings to enums."""
    batch_operations = []
    operation_map = {
        "parse": BatchOperation.PARSE,
        "complexity": BatchOperation.COMPLEXITY,
        "dependency_graph": BatchOperation.DEPENDENCY_GRAPH,
        "html_tree": BatchOperation.HTML_TREE,
        "serialize": BatchOperation.SERIALIZE,
    }

    for op in operations:
        if op in operation_map:
            batch_operations.append(operation_map[op])

    return batch_operations


def _display_operation_result(operation, result) -> None:
    """Display results for a single operation."""
    click.echo(f"\n{operation.value.upper()}:")
    click.echo(f"  Input items: {result.input_count}")
    click.echo(f"  Successful: {result.successful_count}")
    click.echo(f"  Failed: {result.failed_count}")
    click.echo(f"  Success rate: {result.success_rate:.1f}%")
    click.echo(f"  Processing time: {result.total_time:.2f}s")

    _display_output_files(result)
    _display_errors(result)


def _display_output_files(result) -> None:
    """Display output files for a result."""
    if not result.output_files:
        return

    click.echo(f"  Output files: {len(result.output_files)}")
    if len(result.output_files) <= 5:
        for file_path in result.output_files:
            click.echo(f"    - {file_path}")
    else:
        click.echo(
            f"    - {result.output_files[0]} (and {len(result.output_files) - 1} more)",
        )


def _display_errors(result) -> None:
    """Display errors for a result."""
    if not result.errors:
        return

    click.echo(f"  Errors: {len(result.errors)}")
    if len(result.errors) <= 3:
        for error in result.errors:
            click.echo(f"    - {error}")
    else:
        click.echo(f"    - {result.errors[0]} (and {len(result.errors) - 1} more)")


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

    batch_operations = _convert_operations(operations)

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

    start_time = time.time()

    try:
        if input_path.is_file():
            results = processor.process_large_file(
                input_path,
                batch_operations,
                output_dir,
            )
        else:
            results = processor.process_directory(
                input_path,
                batch_operations,
                output_dir,
                pattern,
                recursive,
            )

        total_time = time.time() - start_time

        if progress:
            click.echo()  # New line after progress

        click.echo(f"\n📊 Batch Processing Results ({total_time:.2f}s)")
        click.echo("=" * 50)

        for operation, result in results.items():
            _display_operation_result(operation, result)

        _save_batch_results(results, output_dir)
        click.echo(f"\n✅ Results saved to: {output_dir}")
    except Exception as e:
        click.echo(f"\n❌ Error during batch processing: {e}", err=True)
        raise click.Abort from None


def _save_batch_results(results, output_dir) -> None:
    """Save batch processing results to JSON."""
    results_file = output_dir / "batch_results.json"
    results_data = {
        operation.value: {
            "input_count": result.input_count,
            "successful_count": result.successful_count,
            "failed_count": result.failed_count,
            "success_rate": result.success_rate,
            "total_time": result.total_time,
            "output_files": result.output_files,
            "errors": result.errors,
            "summary": result.summary,
        }
        for operation, result in results.items()
    }

    with Path(results_file).open("w") as f:
        json.dump(results_data, f, indent=2)


def _get_parse_iterator(
    parser,
    input_path: Path,
    split_rules: bool,
    pattern: str,
    recursive: bool,
):
    """Get appropriate parse iterator based on input type."""
    if input_path.is_file():
        if split_rules:
            return parser.parse_rules_from_file(input_path)
        return parser.parse_files([input_path])
    return parser.parse_directory(input_path, pattern, recursive)


def _display_stream_summary(results, total_time: float):
    """Display streaming parse summary."""
    successful = [r for r in results if r.status.value == "success"]
    failed = [r for r in results if r.status.value == "error"]

    click.echo(f"\n📊 Streaming Parse Results ({total_time:.2f}s)")
    click.echo("=" * 40)
    click.echo(f"Total files/rules processed: {len(results)}")
    click.echo(f"Successful: {len(successful)}")
    click.echo(f"Failed: {len(failed)}")
    click.echo(f"Success rate: {len(successful) / len(results) * 100:.1f}%")

    return successful, failed


def _display_stream_details(successful, failed, parser_stats) -> None:
    """Display detailed streaming statistics."""
    if successful:
        total_rules = sum(r.rule_count for r in successful)
        total_imports = sum(r.import_count for r in successful)
        avg_parse_time = sum(r.parse_time for r in successful) / len(successful)

        click.echo(f"Total rules parsed: {total_rules}")
        click.echo(f"Total imports: {total_imports}")
        click.echo(f"Average parse time: {avg_parse_time * 1000:.2f}ms")

    if parser_stats["peak_memory_mb"] > 0:
        click.echo(f"Peak memory usage: {parser_stats['peak_memory_mb']:.1f} MB")

    if failed:
        click.echo("\n❌ Failed files:")
        for result in failed[:5]:
            file_name = Path(result.file_path or "unknown").name
            click.echo(f"  - {file_name}: {result.error}")

        if len(failed) > 5:
            click.echo(f"  ... and {len(failed) - 5} more")


def _save_stream_results(
    output: str,
    results,
    successful,
    failed,
    total_time: float,
    parser_stats,
) -> None:
    """Save streaming results to file."""
    output_data = {
        "summary": {
            "total_processed": len(results),
            "successful": len(successful),
            "failed": len(failed),
            "success_rate": len(successful) / len(results) * 100,
            "total_time": total_time,
            "parser_stats": parser_stats,
        },
        "results": [
            {
                "file_path": r.file_path,
                "rule_name": r.rule_name,
                "status": r.status.value,
                "error": r.error,
                "parse_time": r.parse_time,
                "rule_count": r.rule_count,
                "import_count": r.import_count,
            }
            for r in results
        ],
    }

    with Path(output).open("w") as f:
        json.dump(output_data, f, indent=2)

    click.echo(f"\n📁 Detailed results saved to: {output}")


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

    start_time = time.time()
    results = []

    try:
        result_iter = _get_parse_iterator(
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

        # Display statistics
        successful, failed = _display_stream_summary(results, total_time)

        # Parser statistics
        parser_stats = parser.get_statistics()
        _display_stream_details(successful, failed, parser_stats)

        # Save results if requested
        if output:
            _save_stream_results(
                output,
                results,
                successful,
                failed,
                total_time,
                parser_stats,
            )

    except KeyboardInterrupt:
        parser.cancel()
        click.echo("\n⏹️  Parsing cancelled by user")
    except Exception as e:
        click.echo(f"\n❌ Error during streaming parse: {e}", err=True)
        raise click.Abort from None


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
def _collect_file_paths(input_paths: tuple) -> list[Path]:
    """Collect all YARA files from input paths."""
    file_paths = []
    for path in input_paths:
        path = Path(path)
        if path.is_file():
            file_paths.append(path)
        elif path.is_dir():
            file_paths.extend(path.rglob("*.yar"))
    return file_paths


def _extract_successful_asts(parse_jobs, file_paths: list[Path], chunk_size: int):
    """Extract successful ASTs from parse jobs."""
    successful_asts = []
    file_names = []

    for job_index, job in enumerate(parse_jobs):
        if _is_job_successful(job):
            asts, names = _process_job_results(job, job_index, file_paths, chunk_size)
            successful_asts.extend(asts)
            file_names.extend(names)

    return successful_asts, file_names


def _is_job_successful(job) -> bool:
    """Check if a parse job completed successfully."""
    return job.status.value == "completed" and job.result


def _process_job_results(job, job_index: int, file_paths: list[Path], chunk_size: int):
    """Process results from a successful job."""
    asts = []
    names = []

    for i, ast in enumerate(job.result):
        if not hasattr(ast, "_parse_error"):
            asts.append(ast)
            file_name = _get_corresponding_file_name(job_index, i, file_paths, chunk_size)
            if file_name:
                names.append(file_name)

    return asts, names


def _get_corresponding_file_name(
    job_index: int, ast_index: int, file_paths: list[Path], chunk_size: int
):
    """Get the file name corresponding to a specific AST."""
    start_idx = job_index * chunk_size
    file_idx = start_idx + ast_index
    return str(file_paths[file_idx]) if file_idx < len(file_paths) else None


def _perform_complexity_analysis(
    analyzer,
    successful_asts,
    file_names,
    output_dir: Path,
) -> None:
    """Perform complexity analysis and save results."""
    click.echo("\n🧮 Analyzing complexity...")
    complexity_jobs = analyzer.analyze_complexity_parallel(successful_asts, file_names)

    # Save complexity results
    complexity_results = []
    for job in complexity_jobs:
        if job.status.value == "completed":
            complexity_results.append(job.result)

    if complexity_results:
        complexity_file = output_dir / "complexity_analysis.json"
        with Path(complexity_file).open("w") as f:
            json.dump(complexity_results, f, indent=2)

        click.echo(f"📊 Complexity analysis saved to: {complexity_file}")

        # Show summary statistics
        quality_scores = [r["quality_score"] for r in complexity_results]
        avg_quality = sum(quality_scores) / len(quality_scores)

        click.echo(f"   Average quality score: {avg_quality:.1f}")
        click.echo(
            f"   Quality range: {min(quality_scores):.1f} - {max(quality_scores):.1f}",
        )


def _perform_dependency_analysis(analyzer, successful_asts, output_dir: Path) -> None:
    """Perform dependency analysis and generate graphs."""
    click.echo("\n🕸️  Generating dependency graphs...")
    graph_jobs = analyzer.generate_graphs_parallel(
        successful_asts,
        output_dir / "graphs",
        ["full", "rules"],
    )

    successful_graphs = [job for job in graph_jobs if job.status.value == "completed"]
    click.echo(f"📈 Generated {len(successful_graphs)} dependency graphs")


def _display_parallel_summary(
    file_paths,
    successful_asts,
    analyzer_stats,
    total_time: float,
) -> None:
    """Display parallel processing summary."""
    click.echo(f"\n📊 Parallel Processing Summary ({total_time:.2f}s)")
    click.echo("=" * 45)
    click.echo(f"Files processed: {len(file_paths)}")
    click.echo(f"Successfully parsed: {len(successful_asts)}")
    click.echo(f"Jobs submitted: {analyzer_stats['jobs_submitted']}")
    click.echo(f"Jobs completed: {analyzer_stats['jobs_completed']}")
    click.echo(f"Jobs failed: {analyzer_stats['jobs_failed']}")
    click.echo(f"Average job time: {analyzer_stats['avg_job_time']:.3f}s")
    click.echo(f"Workers used: {analyzer_stats['workers_created']}")

    # Speedup calculation
    if analyzer_stats["jobs_completed"] > 0:
        sequential_estimate = analyzer_stats["total_processing_time"]
        speedup = sequential_estimate / total_time if total_time > 0 else 1
        click.echo(f"Estimated speedup: {speedup:.1f}x")


def parallel(
    input_paths: tuple,
    output_dir: str | None,
    max_workers: int | None,
    timeout: float,
    analysis_type: str,
    chunk_size: int,
) -> None:
    """Analyze YARA files in parallel using thread pooling."""
    file_paths = _collect_file_paths(input_paths)

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

    start_time = time.time()

    try:
        with ParallelAnalyzer(max_workers=max_workers, timeout=timeout) as analyzer:
            # Step 1: Parse files in parallel
            click.echo("\n📋 Parsing files...")
            parse_jobs = analyzer.parse_files_parallel(file_paths, chunk_size)

            # Extract successful ASTs
            successful_asts, file_names = _extract_successful_asts(
                parse_jobs,
                file_paths,
                chunk_size,
            )

            click.echo(f"✅ Successfully parsed {len(successful_asts)} files")

            if not successful_asts:
                click.echo("❌ No files parsed successfully")
                return

            # Step 2: Perform analysis
            if analysis_type in ["complexity", "all"]:
                _perform_complexity_analysis(
                    analyzer,
                    successful_asts,
                    file_names,
                    output_dir,
                )

            if analysis_type in ["dependency", "all"]:
                _perform_dependency_analysis(analyzer, successful_asts, output_dir)

        total_time = time.time() - start_time

        # Overall statistics
        analyzer_stats = analyzer.get_statistics()
        _display_parallel_summary(
            file_paths,
            successful_asts,
            analyzer_stats,
            total_time,
        )

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
    optimizer = MemoryOptimizer()

    recommendations = optimizer.optimize_for_large_collection(collection_size)

    click.echo(f"🎯 Optimization Recommendations for {collection_size:,} files")
    click.echo("=" * 55)

    click.echo("\n📊 Recommended Settings:")
    click.echo(f"  Batch size: {recommendations['batch_size']}")
    click.echo(f"  GC threshold: {recommendations['gc_threshold']}")
    click.echo(f"  Memory limit: {recommendations['memory_limit_mb']} MB")
    click.echo(
        f"  Enable pooling: {'Yes' if recommendations['enable_pooling'] else 'No'}",
    )
    click.echo(
        f"  Use streaming: {'Yes' if recommendations['use_streaming'] else 'No'}",
    )

    click.echo("\n🚀 Performance Strategy:")
    if collection_size < 100:
        click.echo("  • Use standard parallel processing")
        click.echo("  • Memory optimization not critical")
    elif collection_size < 1000:
        click.echo("  • Use batch processing with moderate parallelism")
        click.echo("  • Enable object pooling")
        click.echo("  • Monitor memory usage")
    else:
        click.echo("  • Use streaming parser with small batches")
        click.echo("  • Enable aggressive memory management")
        click.echo("  • Consider distributed processing")

    # Memory recommendations
    if memory_mb:
        click.echo(f"\n💾 Memory Planning (Available: {memory_mb} MB):")

        estimated_memory = collection_size * 0.5  # MB per file estimate

        if estimated_memory > memory_mb:
            click.echo(f"  ⚠️  Estimated memory need: {estimated_memory:.0f} MB")
            click.echo(
                f"  🔧 Use streaming with batch size: {max(1, (memory_mb * 2) // collection_size)}",
            )
            click.echo("  🔧 Enable aggressive garbage collection")
        else:
            click.echo("  ✅ Memory sufficient for batch processing")
            click.echo(
                f"  💡 Can use batch size up to: {recommendations['batch_size'] * 2}",
            )

    # Time recommendations
    if target_time:
        click.echo(f"\n⏱️  Time Optimization (Target: {target_time}s):")

        # Rough time estimates
        estimated_time_sequential = collection_size * 0.1  # seconds per file
        max_workers = 8  # reasonable default
        estimated_time_parallel = estimated_time_sequential / max_workers

        if estimated_time_parallel > target_time:
            needed_workers = int(estimated_time_sequential / target_time)
            click.echo(f"  ⚠️  Estimated time: {estimated_time_parallel:.0f}s")
            click.echo(f"  🔧 Consider {min(needed_workers, 32)} workers")
            click.echo("  🔧 Use smaller analysis operations")
        else:
            click.echo(f"  ✅ Target time achievable with {max_workers} workers")

    click.echo("\n📋 Command Examples:")
    click.echo("  # Batch processing:")
    click.echo("  yaraast performance batch /path/to/rules \\")
    click.echo(f"    --batch-size {recommendations['batch_size']} \\")
    click.echo(f"    --memory-limit {recommendations['memory_limit_mb']} \\")
    click.echo(f"    --max-workers {min(8, max(2, collection_size // 100))}")

    click.echo("\n  # Streaming parsing:")
    click.echo("  yaraast performance stream /path/to/rules \\")
    click.echo(f"    --memory-limit {recommendations['memory_limit_mb'] // 2} \\")
    click.echo("    --progress")
