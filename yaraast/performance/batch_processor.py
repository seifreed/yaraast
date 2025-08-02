"""Batch processing utilities for large YARA rule collections."""

import json
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.metrics import HtmlTreeGenerator
from yaraast.performance.parallel_analyzer import ParallelAnalyzer
from yaraast.performance.streaming_parser import StreamingParser


class BatchOperation(Enum):
    """Types of batch operations."""

    PARSE = "parse"
    COMPLEXITY = "complexity"
    DEPENDENCY_GRAPH = "dependency_graph"
    HTML_TREE = "html_tree"
    SERIALIZE = "serialize"
    VALIDATE = "validate"


@dataclass
class BatchResult:
    """Result of a batch processing operation."""

    operation: BatchOperation
    input_count: int
    successful_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    total_time: float = 0.0
    output_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.input_count == 0:
            return 0.0
        return (self.successful_count / self.input_count) * 100

    @property
    def avg_processing_time(self) -> float:
        """Calculate average processing time per item."""
        if self.successful_count == 0:
            return 0.0
        return self.total_time / self.successful_count


class BatchProcessor:
    """High-performance batch processor for large YARA rule collections.

    This processor combines streaming parsing with parallel analysis to handle
    huge rule sets efficiently while maintaining memory usage within limits.
    """

    def __init__(
        self,
        max_workers: int | None = None,
        max_memory_mb: int = 1000,
        batch_size: int = 50,
        temp_dir: str | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ):
        """Initialize batch processor.

        Args:
            max_workers: Maximum worker threads for parallel processing
            max_memory_mb: Maximum memory usage before triggering cleanup
            batch_size: Number of items to process in each batch
            temp_dir: Temporary directory for intermediate files
            progress_callback: Callback for progress updates
        """
        self.max_workers = max_workers
        self.max_memory_mb = max_memory_mb
        self.batch_size = batch_size
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.progress_callback = progress_callback

        # Initialize components
        self.streaming_parser = StreamingParser(
            max_memory_mb=max_memory_mb, progress_callback=self._streaming_progress_callback
        )

        self._stats = {
            "batches_processed": 0,
            "total_files": 0,
            "total_rules": 0,
            "total_processing_time": 0.0,
            "peak_memory_mb": 0,
            "errors_encountered": 0,
        }

    def process_directory(
        self,
        directory: str | Path,
        operations: list[BatchOperation],
        output_dir: str | Path | None = None,
        file_pattern: str = "*.yar",
        recursive: bool = True,
    ) -> dict[BatchOperation, BatchResult]:
        """Process all YARA files in a directory with specified operations.

        Args:
            directory: Directory containing YARA files
            operations: List of operations to perform
            output_dir: Directory for output files
            file_pattern: File pattern to match
            recursive: Whether to scan subdirectories recursively

        Returns:
            Dictionary mapping operations to their results
        """
        directory = Path(directory)
        output_dir = Path(output_dir) if output_dir else directory / "batch_output"
        output_dir.mkdir(exist_ok=True)

        # Find all YARA files
        if recursive:
            file_paths = list(directory.rglob(file_pattern))
        else:
            file_paths = list(directory.glob(file_pattern))

        return self.process_files(file_paths, operations, output_dir)

    def process_files(
        self, file_paths: list[str | Path], operations: list[BatchOperation], output_dir: str | Path
    ) -> dict[BatchOperation, BatchResult]:
        """Process a list of YARA files with specified operations.

        Args:
            file_paths: List of file paths to process
            operations: List of operations to perform
            output_dir: Directory for output files

        Returns:
            Dictionary mapping operations to their results
        """
        file_paths = [Path(p) for p in file_paths]
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)

        results = {}

        # Step 1: Parse all files (streaming)
        if self.progress_callback:
            self.progress_callback("Parsing files", 0, len(file_paths))

        parsed_asts = []
        parse_results = []

        for result in self.streaming_parser.parse_files(file_paths):
            parse_results.append(result)
            if result.ast:
                parsed_asts.append((result.file_path, result.ast))

        # Create parse result summary
        successful_parses = [r for r in parse_results if r.ast is not None]
        failed_parses = [r for r in parse_results if r.ast is None]

        parse_batch_result = BatchResult(
            operation=BatchOperation.PARSE,
            input_count=len(file_paths),
            successful_count=len(successful_parses),
            failed_count=len(failed_parses),
            total_time=sum(r.parse_time for r in parse_results),
            errors=[r.error for r in failed_parses if r.error],
        )
        results[BatchOperation.PARSE] = parse_batch_result

        # Update stats
        self._stats["total_files"] = len(file_paths)
        self._stats["total_rules"] = sum(r.rule_count for r in successful_parses)

        # Step 2: Process other operations in parallel
        if parsed_asts:
            for operation in operations:
                if operation == BatchOperation.PARSE:
                    continue  # Already done

                result = self._process_operation(operation, parsed_asts, output_dir)
                results[operation] = result

        return results

    def process_large_file(
        self,
        file_path: str | Path,
        operations: list[BatchOperation],
        output_dir: str | Path,
        split_rules: bool = True,
    ) -> dict[BatchOperation, BatchResult]:
        """Process a very large YARA file by splitting it into individual rules.

        Args:
            file_path: Path to large YARA file
            operations: List of operations to perform
            output_dir: Directory for output files
            split_rules: Whether to split file into individual rules

        Returns:
            Dictionary mapping operations to their results
        """
        file_path = Path(file_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)

        results = {}

        if split_rules:
            # Parse individual rules from the large file
            rule_results = list(self.streaming_parser.parse_rules_from_file(file_path))

            # Extract successful ASTs
            parsed_asts = []
            for result in rule_results:
                if result.ast:
                    rule_name = result.rule_name or f"rule_{len(parsed_asts)}"
                    parsed_asts.append((f"{file_path}:{rule_name}", result.ast))

            # Create parse result
            successful_count = len(parsed_asts)
            failed_count = len(rule_results) - successful_count

            parse_result = BatchResult(
                operation=BatchOperation.PARSE,
                input_count=len(rule_results),
                successful_count=successful_count,
                failed_count=failed_count,
                total_time=sum(getattr(r, "parse_time", 0) for r in rule_results),
            )
            results[BatchOperation.PARSE] = parse_result
        else:
            # Parse entire file as one unit
            return self.process_files([file_path], operations, output_dir)

        # Process other operations
        for operation in operations:
            if operation == BatchOperation.PARSE:
                continue

            result = self._process_operation(operation, parsed_asts, output_dir)
            results[operation] = result

        return results

    def get_statistics(self) -> dict[str, Any]:
        """Get batch processing statistics."""
        return self._stats.copy()

    def _process_operation(
        self, operation: BatchOperation, parsed_asts: list[tuple], output_dir: Path
    ) -> BatchResult:
        """Process a specific operation on parsed ASTs."""
        time.time()

        if operation == BatchOperation.COMPLEXITY:
            return self._process_complexity_analysis(parsed_asts, output_dir)
        if operation == BatchOperation.DEPENDENCY_GRAPH:
            return self._process_dependency_graphs(parsed_asts, output_dir)
        if operation == BatchOperation.HTML_TREE:
            return self._process_html_trees(parsed_asts, output_dir)
        if operation == BatchOperation.SERIALIZE:
            return self._process_serialization(parsed_asts, output_dir)
        if operation == BatchOperation.VALIDATE:
            return self._process_validation(parsed_asts, output_dir)
        raise ValueError(f"Unknown operation: {operation}")

    def _process_complexity_analysis(
        self, parsed_asts: list[tuple], output_dir: Path
    ) -> BatchResult:
        """Process complexity analysis for all ASTs."""
        result = BatchResult(operation=BatchOperation.COMPLEXITY, input_count=len(parsed_asts))

        start_time = time.time()

        with ParallelAnalyzer(max_workers=self.max_workers) as analyzer:
            # Extract ASTs and file names
            asts = [ast for _, ast in parsed_asts]
            file_names = [name for name, _ in parsed_asts]

            # Analyze in parallel
            jobs = analyzer.analyze_complexity_parallel(asts, file_names)

            # Collect results
            complexity_results = []
            for job in jobs:
                if job.status.value == "completed":
                    complexity_results.append(job.result)
                    result.successful_count += 1
                else:
                    result.failed_count += 1
                    if job.error:
                        result.errors.append(job.error)

        # Save complexity report
        if complexity_results:
            output_file = output_dir / "complexity_analysis.json"
            with open(output_file, "w") as f:
                json.dump(complexity_results, f, indent=2)
            result.output_files.append(str(output_file))

            # Create summary
            quality_scores = [r["quality_score"] for r in complexity_results]
            result.summary = {
                "avg_quality_score": sum(quality_scores) / len(quality_scores),
                "min_quality_score": min(quality_scores),
                "max_quality_score": max(quality_scores),
                "total_rules_analyzed": sum(
                    r["metrics"]["file_metrics"]["total_rules"] for r in complexity_results
                ),
            }

        result.total_time = time.time() - start_time
        return result

    def _process_dependency_graphs(self, parsed_asts: list[tuple], output_dir: Path) -> BatchResult:
        """Process dependency graph generation for all ASTs."""
        result = BatchResult(
            operation=BatchOperation.DEPENDENCY_GRAPH, input_count=len(parsed_asts)
        )

        start_time = time.time()
        graphs_dir = output_dir / "dependency_graphs"
        graphs_dir.mkdir(exist_ok=True)

        with ParallelAnalyzer(max_workers=self.max_workers) as analyzer:
            asts = [ast for _, ast in parsed_asts]

            # Generate graphs in parallel
            jobs = analyzer.generate_graphs_parallel(
                asts, output_dir=graphs_dir, graph_types=["full", "rules"]
            )

            # Collect results
            for job in jobs:
                if job.status.value == "completed":
                    result.successful_count += 1
                    if "output_file" in job.result:
                        result.output_files.append(job.result["output_file"])
                else:
                    result.failed_count += 1
                    if job.error:
                        result.errors.append(job.error)

        result.total_time = time.time() - start_time
        result.summary = {"graphs_generated": len(result.output_files)}
        return result

    def _process_html_trees(self, parsed_asts: list[tuple], output_dir: Path) -> BatchResult:
        """Process HTML tree generation for all ASTs."""
        result = BatchResult(operation=BatchOperation.HTML_TREE, input_count=len(parsed_asts))

        start_time = time.time()
        trees_dir = output_dir / "html_trees"
        trees_dir.mkdir(exist_ok=True)

        generator = HtmlTreeGenerator()

        for i, (file_name, ast) in enumerate(parsed_asts):
            try:
                # Create safe filename
                safe_name = Path(file_name).stem.replace(":", "_").replace("/", "_")
                output_file = trees_dir / f"{safe_name}_{i}.html"

                # Generate HTML tree
                generator.generate_interactive_html(ast, str(output_file), f"AST: {file_name}")

                result.successful_count += 1
                result.output_files.append(str(output_file))

            except Exception as e:
                result.failed_count += 1
                result.errors.append(f"{file_name}: {e!s}")

        result.total_time = time.time() - start_time
        result.summary = {"html_files_generated": len(result.output_files)}
        return result

    def _process_serialization(self, parsed_asts: list[tuple], output_dir: Path) -> BatchResult:
        """Process AST serialization for all ASTs."""
        result = BatchResult(operation=BatchOperation.SERIALIZE, input_count=len(parsed_asts))

        start_time = time.time()
        serialized_dir = output_dir / "serialized"
        serialized_dir.mkdir(exist_ok=True)

        from yaraast.serialization import JsonSerializer

        serializer = JsonSerializer()

        for i, (file_name, ast) in enumerate(parsed_asts):
            try:
                # Create safe filename
                safe_name = Path(file_name).stem.replace(":", "_").replace("/", "_")
                output_file = serialized_dir / f"{safe_name}_{i}.json"

                # Serialize AST
                serializer.serialize(ast, str(output_file))

                result.successful_count += 1
                result.output_files.append(str(output_file))

            except Exception as e:
                result.failed_count += 1
                result.errors.append(f"{file_name}: {e!s}")

        result.total_time = time.time() - start_time
        result.summary = {"serialized_files": len(result.output_files)}
        return result

    def _process_validation(self, parsed_asts: list[tuple], output_dir: Path) -> BatchResult:
        """Process AST validation for all ASTs."""
        result = BatchResult(operation=BatchOperation.VALIDATE, input_count=len(parsed_asts))

        start_time = time.time()
        validation_issues = []

        for file_name, ast in parsed_asts:
            issues = self._validate_ast(ast, file_name)
            if issues:
                validation_issues.extend(issues)
                result.failed_count += 1
            else:
                result.successful_count += 1

        # Save validation report
        if validation_issues:
            output_file = output_dir / "validation_report.json"
            with open(output_file, "w") as f:
                json.dump(validation_issues, f, indent=2)
            result.output_files.append(str(output_file))

        result.total_time = time.time() - start_time
        result.summary = {
            "total_issues": len(validation_issues),
            "files_with_issues": result.failed_count,
        }
        result.errors = [issue["message"] for issue in validation_issues]

        return result

    def _validate_ast(self, ast: YaraFile, file_name: str) -> list[dict[str, Any]]:
        """Validate an AST and return list of issues."""
        issues = []

        # Check for empty rules
        for rule in ast.rules:
            if not rule.strings and not rule.condition:
                issues.append(
                    {
                        "file": file_name,
                        "rule": rule.name,
                        "type": "empty_rule",
                        "message": f"Rule '{rule.name}' has no strings or condition",
                    }
                )

            # Check for unused strings
            if rule.strings and rule.condition:
                # Simple check - this could be more sophisticated
                condition_str = str(rule.condition)
                for string_def in rule.strings:
                    if string_def.identifier not in condition_str:
                        issues.append(
                            {
                                "file": file_name,
                                "rule": rule.name,
                                "type": "unused_string",
                                "message": f"String '{string_def.identifier}' is not used in condition",
                            }
                        )

        return issues

    def _streaming_progress_callback(self, current: int, total: int, current_file: str) -> None:
        """Progress callback for streaming parser."""
        if self.progress_callback:
            self.progress_callback(f"Parsing {Path(current_file).name}", current, total)
