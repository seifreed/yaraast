"""Reporting helpers for performance CLI."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.utils import write_json


def display_operation_result(operation, result) -> None:
    """Display results for a single operation."""
    click.echo(f"\n{operation.value.upper()}:")
    click.echo(f"  Input items: {result.input_count}")
    click.echo(f"  Successful: {result.successful_count}")
    click.echo(f"  Failed: {result.failed_count}")
    click.echo(f"  Success rate: {result.success_rate:.1f}%")
    click.echo(f"  Processing time: {result.total_time:.2f}s")

    _display_list_summary("Output files", result.output_files, max_preview=5)
    _display_list_summary("Errors", result.errors, max_preview=3)


def display_stream_summary(results, total_time: float):
    """Display streaming parse summary."""
    from yaraast.cli.performance_services import summarize_stream_results

    summary = summarize_stream_results(results)
    successful = summary["successful"]
    failed = summary["failed"]

    click.echo(f"\n📊 Streaming Parse Results ({total_time:.2f}s)")
    click.echo("=" * 40)
    click.echo(f"Total files/rules processed: {len(results)}")
    click.echo(f"Successful: {len(successful)}")
    click.echo(f"Failed: {len(failed)}")
    click.echo(f"Success rate: {len(successful) / len(results) * 100:.1f}%")

    return successful, failed


def display_stream_details(successful, failed, parser_stats) -> None:
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


def display_parallel_summary(summary: dict, total_time: float) -> None:
    """Display parallel processing summary."""
    click.echo(f"\n📊 Parallel Processing Summary ({total_time:.2f}s)")
    click.echo("=" * 45)
    click.echo(f"Files processed: {summary['files_processed']}")
    click.echo(f"Successfully parsed: {summary['successful']}")
    click.echo(f"Jobs submitted: {summary['jobs_submitted']}")
    click.echo(f"Jobs completed: {summary['jobs_completed']}")
    click.echo(f"Jobs failed: {summary['jobs_failed']}")
    click.echo(f"Average job time: {summary['avg_job_time']:.3f}s")
    click.echo(f"Workers used: {summary['workers_used']}")
    click.echo(f"Estimated speedup: {summary['speedup']:.1f}x")


def report_complexity_analysis(
    complexity_results: list[dict],
    output_dir: Path,
) -> None:
    if not complexity_results:
        return

    click.echo("\n🧮 Analyzing complexity...")
    complexity_file = output_dir / "complexity_analysis.json"
    write_json(complexity_file, complexity_results)

    click.echo(f"📊 Complexity analysis saved to: {complexity_file}")

    quality_scores = [r["quality_score"] for r in complexity_results if "quality_score" in r]
    if quality_scores:
        avg_quality = sum(quality_scores) / len(quality_scores)
        click.echo(f"   Average quality score: {avg_quality:.1f}")
        click.echo(
            f"   Quality range: {min(quality_scores):.1f} - {max(quality_scores):.1f}",
        )


def display_optimize_report(plan: dict) -> None:
    recommendations = plan["recommendations"]
    collection_size = plan["collection_size"]

    click.echo(f"🎯 Optimization Recommendations for {collection_size:,} files")
    click.echo("=" * 55)

    click.echo("\n📊 Recommended Settings:")
    click.echo(f"  Batch size: {recommendations['batch_size']}")
    gc_threshold = recommendations.get("gc_threshold")
    if gc_threshold is not None:
        click.echo(f"  GC threshold: {gc_threshold}")
    click.echo(f"  Memory limit: {recommendations['memory_limit_mb']} MB")
    click.echo(
        f"  Enable pooling: {'Yes' if recommendations['enable_pooling'] else 'No'}",
    )
    click.echo(
        f"  Use streaming: {'Yes' if recommendations['use_streaming'] else 'No'}",
    )

    click.echo("\n🚀 Performance Strategy:")
    for line in plan["strategy"]:
        click.echo(f"  • {line}")

    memory_plan = plan.get("memory_plan")
    if memory_plan:
        click.echo(f"\n💾 Memory Planning (Available: {memory_plan['available_mb']} MB):")
        if memory_plan["sufficient"]:
            click.echo("  ✅ Memory sufficient for batch processing")
            click.echo(
                f"  💡 Can use batch size up to: {recommendations['batch_size'] * 2}",
            )
        else:
            click.echo(f"  ⚠️  Estimated memory need: {memory_plan['estimated_mb']:.0f} MB")
            click.echo(
                f"  🔧 Use streaming with batch size: {memory_plan['suggested_batch_size']}",
            )
            click.echo("  🔧 Enable aggressive garbage collection")

    time_plan = plan.get("time_plan")
    if time_plan:
        click.echo(f"\n⏱️  Time Optimization (Target: {time_plan['target_time']}s):")
        if time_plan["estimated_time_parallel"] > time_plan["target_time"]:
            click.echo(f"  ⚠️  Estimated time: {time_plan['estimated_time_parallel']:.0f}s")
            click.echo(f"  🔧 Consider {min(time_plan['needed_workers'], 32)} workers")
            click.echo("  🔧 Use smaller analysis operations")
        else:
            click.echo(f"  ✅ Target time achievable with {time_plan['max_workers']} workers")

    examples = plan["examples"]
    click.echo("\n📋 Command Examples:")
    click.echo("  # Batch processing:")
    click.echo("  yaraast performance batch /path/to/rules \\")
    click.echo(f"    --batch-size {examples['batch']['batch_size']} \\")
    click.echo(f"    --memory-limit {examples['batch']['memory_limit_mb']} \\")
    click.echo(f"    --max-workers {examples['batch']['max_workers']}")

    click.echo("\n  # Streaming parsing:")
    click.echo("  yaraast performance stream /path/to/rules \\")
    click.echo(f"    --memory-limit {examples['stream']['memory_limit_mb']} \\")
    click.echo("    --progress")


def _display_list_summary(label: str, items: list, max_preview: int) -> None:
    """Display a list summary with a compact preview."""
    if not items:
        return

    click.echo(f"  {label}: {len(items)}")
    if len(items) <= max_preview:
        for item in items:
            click.echo(f"    - {item}")
    else:
        click.echo(f"    - {items[0]} (and {len(items) - 1} more)")
