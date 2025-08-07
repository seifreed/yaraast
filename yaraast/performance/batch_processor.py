"""Batch processing utilities for large YARA rule collections."""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


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
    """High-performance batch processor for large YARA rule collections."""

    def __init__(
        self,
        max_workers: int | None = None,
        max_memory_mb: int = 1000,
        batch_size: int = 50,
        temp_dir: str | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> None:
        """Initialize batch processor."""
        self.max_workers = max_workers or 4
        self.max_memory_mb = max_memory_mb
        self.batch_size = batch_size
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.progress_callback = progress_callback
        self._stats = {
            "batches_processed": 0,
            "items_processed": 0,
            "failures": 0,
        }

    def process_batch(
        self,
        items: list[Any],
        operation: BatchOperation | Callable[[Any], Any] | None = None,
        batch_size: int | None = None,
    ) -> list[Any]:
        """Process a batch of items."""
        batch_size = batch_size or self.batch_size
        results = []

        # Process in batches
        for i in range(0, len(items), batch_size):
            batch = items[i : i + batch_size]

            for item in batch:
                try:
                    if callable(operation):
                        result = operation(item)
                    else:
                        result = self._process_item(item, operation)
                    results.append(result)
                    self._stats["items_processed"] += 1
                except (ValueError, TypeError, AttributeError):
                    self._stats["failures"] += 1
                    results.append(None)

            self._stats["batches_processed"] += 1

            # Progress callback
            if self.progress_callback:
                self.progress_callback("Processing", i + len(batch), len(items))

        return results

    def _process_item(self, item: Any, operation: BatchOperation | None) -> Any:
        """Process a single item based on operation type."""
        if operation == BatchOperation.PARSE:
            return self._parse_item(item)
        if operation == BatchOperation.COMPLEXITY:
            return self._analyze_complexity(item)
        if operation == BatchOperation.SERIALIZE:
            return self._serialize_item(item)
        if operation == BatchOperation.VALIDATE:
            return self._validate_item(item)
        return item

    def _parse_item(self, item: str | Path) -> YaraFile | None:
        """Parse a YARA file."""
        try:
            parser = Parser()
            if isinstance(item, Path):
                with open(item) as f:
                    content = f.read()
            else:
                content = item
            return parser.parse(content)
        except (ValueError, TypeError, AttributeError):
            return None

    def _analyze_complexity(self, item: Rule) -> dict[str, Any]:
        """Analyze rule complexity."""
        analyzer = RuleAnalyzer()
        return analyzer.analyze(item)

    def _serialize_item(self, item: Any) -> str:
        """Serialize an item to JSON."""
        serializer = JsonSerializer()
        return serializer.serialize(item)

    def _validate_item(self, item: Rule) -> bool:
        """Validate a rule."""
        # Basic validation
        return bool(item.name and item.condition)

    def process_files(
        self,
        file_paths: list[Path],
        operation: BatchOperation,
        output_dir: Path | None = None,
    ) -> BatchResult:
        """Process multiple YARA files."""
        start_time = time.time()
        result = BatchResult(
            operation=operation,
            input_count=len(file_paths),
        )

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

        # Process files
        for i, file_path in enumerate(file_paths):
            try:
                # Parse file
                with open(file_path) as f:
                    content = f.read()

                parsed = self._parse_item(content)
                if not parsed:
                    result.failed_count += 1
                    result.errors.append(f"Failed to parse {file_path}")
                    continue

                # Perform operation
                if operation == BatchOperation.COMPLEXITY:
                    for rule in parsed.rules:
                        analysis = self._analyze_complexity(rule)
                        result.summary[rule.name] = analysis

                elif operation == BatchOperation.SERIALIZE and output_dir:
                    output_file = output_dir / f"{file_path.stem}.json"
                    json_content = self._serialize_item(parsed)
                    output_file.write_text(json_content)
                    result.output_files.append(str(output_file))

                result.successful_count += 1

            except Exception as e:
                result.failed_count += 1
                result.errors.append(f"Error processing {file_path}: {e!s}")

            # Progress callback
            if self.progress_callback:
                self.progress_callback(
                    f"Processing {operation.value}",
                    i + 1,
                    len(file_paths),
                )

        result.total_time = time.time() - start_time
        return result

    def process_rules(
        self,
        rules: list[Rule],
        operation: Callable[[Rule], Any],
    ) -> list[Any]:
        """Process a list of rules with a custom operation."""
        return self.process_batch(rules, operation)

    def analyze_rules(self, rules: list[Rule]) -> list[dict[str, Any]]:
        """Analyze a batch of rules."""
        return self.process_batch(rules, BatchOperation.COMPLEXITY)

    def optimize_rules(self, rules: list[Rule]) -> list[Rule]:
        """Optimize a batch of rules."""
        from yaraast.optimization.rule_optimizer import RuleOptimizer

        optimizer = RuleOptimizer()
        return self.process_batch(rules, optimizer.optimize_rule)

    def get_statistics(self) -> dict[str, Any]:
        """Get processing statistics."""
        return {
            **self._stats,
            "avg_batch_size": (
                self._stats["items_processed"] / self._stats["batches_processed"]
                if self._stats["batches_processed"] > 0
                else 0
            ),
            "failure_rate": (
                self._stats["failures"] / self._stats["items_processed"] * 100
                if self._stats["items_processed"] > 0
                else 0
            ),
        }

    def reset_statistics(self) -> None:
        """Reset processing statistics."""
        self._stats = {
            "batches_processed": 0,
            "items_processed": 0,
            "failures": 0,
        }
