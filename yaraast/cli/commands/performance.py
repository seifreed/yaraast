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
def performance():
    """Performance tools for large YARA rule collections."""


@performance.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output-dir", "-o", type=click.Path(), help="Output directory")
@click.option("--batch-size", "-b", type=int, default=50, help="Batch size for processing")
@click.option("--max-workers", "-w", type=int, help="Maximum worker threads")
@click.option("--memory-limit", "-m", type=int, default=1000, help="Memory limit in MB")
@click.option(
    "--operations",
    "-op",
    multiple=True,
    type=click.Choice(["parse", "complexity", "dependency_graph", "html_tree", "serialize"]),
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
):
    """Process large collections of YARA files in batches."""
    input_path = Path(input_path)

    if not output_dir:
        output_dir = input_path.parent / f"{input_path.name}_batch_output"
    output_dir = Path(output_dir)

    # Convert operation strings to enums
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

    # Progress callback
    def progress_callback(operation: str, current: int, total: int):
        if progress:
            percentage = (current / total * 100) if total > 0 else 0
            click.echo(f"\r{operation}: {current}/{total} ({percentage:.1f}%)", nl=False)

    # Initialize batch processor
    processor = BatchProcessor(
        max_workers=max_workers,
        max_memory_mb=memory_limit,
        batch_size=batch_size,
        progress_callback=progress_callback,
    )

    start_time = time.time()

    try:
        if input_path.is_file():
            # Process single large file
            results = processor.process_large_file(input_path, batch_operations, output_dir)
        else:
            # Process directory
            results = processor.process_directory(
                input_path, batch_operations, output_dir, pattern, recursive
            )

        total_time = time.time() - start_time

        if progress:
            click.echo()  # New line after progress

        # Display results
        click.echo(f"\n📊 Batch Processing Results ({total_time:.2f}s)")
        click.echo("=" * 50)

        for operation, result in results.items():
            click.echo(f"\n{operation.value.upper()}:")
            click.echo(f"  Input items: {result.input_count}")
            click.echo(f"  Successful: {result.successful_count}")
            click.echo(f"  Failed: {result.failed_count}")
            click.echo(f"  Success rate: {result.success_rate:.1f}%")
            click.echo(f"  Processing time: {result.total_time:.2f}s")

            if result.output_files:
                click.echo(f"  Output files: {len(result.output_files)}")
                if len(result.output_files) <= 5:
                    for file_path in result.output_files:
                        click.echo(f"    - {file_path}")
                else:
                    click.echo(
                        f"    - {result.output_files[0]} (and {len(result.output_files)-1} more)"
                    )

            if result.errors:
                click.echo(f"  Errors: {len(result.errors)}")
                if len(result.errors) <= 3:
                    for error in result.errors:
                        click.echo(f"    - {error}")
                else:
                    click.echo(f"    - {result.errors[0]} (and {len(result.errors)-1} more)")

        # Save detailed results
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

        click.echo(f"\n📁 Detailed results saved to: {results_file}")

        # Overall statistics
        stats = processor.get_statistics()
        if stats["total_files"] > 0:
            click.echo("\n📈 Overall Statistics:")
            click.echo(f"  Total files processed: {stats['total_files']}")
            click.echo(f"  Total rules parsed: {stats['total_rules']}")
            click.echo(
                f"  Average rules per file: {stats['total_rules'] / stats['total_files']:.1f}"
            )
            if stats["peak_memory_mb"] > 0:
                click.echo(f"  Peak memory usage: {stats['peak_memory_mb']:.1f} MB")

    except Exception as e:
        click.echo(f"\n❌ Error during batch processing: {e}", err=True)
        raise click.Abort from None


@performance.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for parsing statistics")
@click.option("--memory-limit", "-m", type=int, default=500, help="Memory limit in MB")
@click.option("--pattern", "-p", default="*.yar", help="File pattern to match")
@click.option("--recursive", "-r", is_flag=True, help="Process directories recursively")
@click.option("--split-rules", is_flag=True, help="Parse individual rules from large files")
@click.option("--progress", is_flag=True, help="Show progress information")
def stream(
    input_path: str,
    output: str | None,
    memory_limit: int,
    pattern: str,
    recursive: bool,
    split_rules: bool,
    progress: bool,
):
    """Stream-parse large YARA collections with minimal memory usage."""
    input_path = Path(input_path)

    # Progress callback
    def progress_callback(current: int, total: int, current_file: str):
        if progress:
            percentage = (current / total * 100) if total > 0 else 0
            file_name = Path(current_file).name
            click.echo(f"\r{current}/{total} ({percentage:.1f}%) - {file_name}", nl=False)

    # Initialize streaming parser
    parser = StreamingParser(
        max_memory_mb=memory_limit, enable_gc=True, progress_callback=progress_callback
    )

    start_time = time.time()
    results = []

    try:
        if input_path.is_file():
            if split_rules:
                # Parse individual rules from file
                result_iter = parser.parse_rules_from_file(input_path)
            else:
                # Parse entire file
                result_iter = parser.parse_files([input_path])
        else:
            # Parse directory
            result_iter = parser.parse_directory(input_path, pattern, recursive)

        # Process results
        for result in result_iter:
            results.append(result)

        total_time = time.time() - start_time

        if progress:
            click.echo()  # New line after progress

        # Display statistics
        successful = [r for r in results if r.status.value == "success"]
        failed = [r for r in results if r.status.value == "error"]

        click.echo(f"\n📊 Streaming Parse Results ({total_time:.2f}s)")
        click.echo("=" * 40)
        click.echo(f"Total files/rules processed: {len(results)}")
        click.echo(f"Successful: {len(successful)}")
        click.echo(f"Failed: {len(failed)}")
        click.echo(f"Success rate: {len(successful) / len(results) * 100:.1f}%")

        if successful:
            total_rules = sum(r.rule_count for r in successful)
            total_imports = sum(r.import_count for r in successful)
            avg_parse_time = sum(r.parse_time for r in successful) / len(successful)

            click.echo(f"Total rules parsed: {total_rules}")
            click.echo(f"Total imports: {total_imports}")
            click.echo(f"Average parse time: {avg_parse_time * 1000:.2f}ms")

        # Parser statistics
        parser_stats = parser.get_statistics()
        if parser_stats["peak_memory_mb"] > 0:
            click.echo(f"Peak memory usage: {parser_stats['peak_memory_mb']:.1f} MB")

        if failed:
            click.echo("\n❌ Failed files:")
            for result in failed[:5]:  # Show first 5 failures
                file_name = Path(result.file_path or "unknown").name
                click.echo(f"  - {file_name}: {result.error}")

            if len(failed) > 5:
                click.echo(f"  ... and {len(failed) - 5} more")

        # Save results if requested
        if output:
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
@click.option("--timeout", "-t", type=float, default=300.0, help="Job timeout in seconds")
@click.option(
    "--analysis-type",
    "-a",
    type=click.Choice(["complexity", "dependency", "all"]),
    default="complexity",
    help="Type of analysis to perform",
)
@click.option("--chunk-size", "-c", type=int, default=10, help="Files per processing chunk")
def parallel(
    input_paths: tuple,
    output_dir: str | None,
    max_workers: int | None,
    timeout: float,
    analysis_type: str,
    chunk_size: int,
):
    """Analyze YARA files in parallel using thread pooling."""
    file_paths = []
    for path in input_paths:
        path = Path(path)
        if path.is_file():
            file_paths.append(path)
        elif path.is_dir():
            file_paths.extend(path.rglob("*.yar"))

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
            successful_asts = []
            file_names = []

            for job in parse_jobs:
                if job.status.value == "completed" and job.result:
                    for i, ast in enumerate(job.result):
                        if not hasattr(ast, "_parse_error"):
                            successful_asts.append(ast)
                            # Get corresponding file name
                            job_index = parse_jobs.index(job)
                            start_idx = job_index * chunk_size
                            file_idx = start_idx + i
                            if file_idx < len(file_paths):
                                file_names.append(str(file_paths[file_idx]))

            click.echo(f"✅ Successfully parsed {len(successful_asts)} files")

            if not successful_asts:
                click.echo("❌ No files parsed successfully")
                return

            # Step 2: Perform analysis
            if analysis_type in ["complexity", "all"]:
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
                        f"   Quality range: {min(quality_scores):.1f} - {max(quality_scores):.1f}"
                    )

            if analysis_type in ["dependency", "all"]:
                click.echo("\n🕸️  Generating dependency graphs...")
                graph_jobs = analyzer.generate_graphs_parallel(
                    successful_asts, output_dir / "graphs", ["full", "rules"]
                )

                successful_graphs = [job for job in graph_jobs if job.status.value == "completed"]
                click.echo(f"📈 Generated {len(successful_graphs)} dependency graphs")

        total_time = time.time() - start_time

        # Overall statistics
        analyzer_stats = analyzer.get_statistics()

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

    except KeyboardInterrupt:
        click.echo("\n⏹️  Analysis cancelled by user")
    except Exception as e:
        click.echo(f"\n❌ Error during parallel analysis: {e}", err=True)
        raise click.Abort from None


@performance.command()
@click.argument("collection_size", type=int)
@click.option("--memory-mb", type=int, help="Available memory in MB")
@click.option("--target-time", type=int, help="Target processing time in seconds")
def optimize(collection_size: int, memory_mb: int | None, target_time: int | None):
    """Get optimization recommendations for processing large collections."""
    optimizer = MemoryOptimizer()

    recommendations = optimizer.optimize_for_large_collection(collection_size)

    click.echo(f"🎯 Optimization Recommendations for {collection_size:,} files")
    click.echo("=" * 55)

    click.echo("\n📊 Recommended Settings:")
    click.echo(f"  Batch size: {recommendations['batch_size']}")
    click.echo(f"  GC threshold: {recommendations['gc_threshold']}")
    click.echo(f"  Memory limit: {recommendations['memory_limit_mb']} MB")
    click.echo(f"  Enable pooling: {'Yes' if recommendations['enable_pooling'] else 'No'}")
    click.echo(f"  Use streaming: {'Yes' if recommendations['use_streaming'] else 'No'}")

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
                f"  🔧 Use streaming with batch size: {max(1, (memory_mb * 2) // collection_size)}"
            )
            click.echo("  🔧 Enable aggressive garbage collection")
        else:
            click.echo("  ✅ Memory sufficient for batch processing")
            click.echo(f"  💡 Can use batch size up to: {recommendations['batch_size'] * 2}")

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
