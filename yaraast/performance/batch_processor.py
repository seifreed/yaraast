"""Batch processing utilities for large YARA rule collections."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from os import PathLike, fspath
from pathlib import Path
import tempfile
from typing import TYPE_CHECKING, Any, overload

from yaraast.performance.batch_processor_ops import (
    analyze_complexity,
    parse_item,
    process_files_multi,
    process_files_single,
    process_large_file as process_large_file_ops,
    serialize_item,
    validate_item,
)
from yaraast.performance.validation import (
    path_exists_and_not_dir,
    validate_file_path_sequence,
    validate_positive_int_setting,
)
from yaraast.shared.file_patterns import FilePatterns, iter_matching_files
from yaraast.shared.path_safety import path_has_symlink_ancestor, path_is_symlink

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


def _validate_process_batch_operation(operation: object) -> None:
    if operation is None or callable(operation) or isinstance(operation, BatchOperation):
        return
    msg = "operation must be a BatchOperation, callable, or None"
    raise TypeError(msg)


def _validate_operation_list(operations: object) -> list[BatchOperation]:
    if not isinstance(operations, list):
        msg = "operations must be a BatchOperation or list of BatchOperation"
        raise TypeError(msg)
    if not operations:
        msg = "operations must not be empty"
        raise ValueError(msg)
    for operation in operations:
        if not isinstance(operation, BatchOperation):
            msg = "operations must contain only BatchOperation values"
            raise TypeError(msg)
    return operations


class BatchProcessor:
    """High-performance batch processor for large YARA rule collections."""

    def __init__(
        self,
        max_workers: int | None = None,
        max_memory_mb: int = 1000,
        batch_size: int = 50,
        file_timeout: float | None = None,
        temp_dir: str | PathLike[str] | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> None:
        """Initialize batch processor."""
        if max_workers is not None:
            validate_positive_int_setting(max_workers, "max_workers")

        validate_positive_int_setting(max_memory_mb, "max_memory_mb")

        validate_positive_int_setting(batch_size, "batch_size")

        self.max_workers = max_workers if max_workers is not None else 4
        self.max_memory_mb = max_memory_mb
        self.batch_size = batch_size
        self.file_timeout = file_timeout
        self.temp_dir = self._require_temp_dir(temp_dir)
        self.progress_callback = progress_callback
        self._stats = {
            "batches_processed": 0,
            "items_processed": 0,
            "failures": 0,
        }

    def _require_temp_dir(self, temp_dir: object) -> Path:
        if temp_dir is None:
            return Path(tempfile.gettempdir())
        if isinstance(temp_dir, bool | bytes) or not isinstance(temp_dir, str | PathLike):
            msg = "temp_dir must be a path"
            raise TypeError(msg)
        raw_path = fspath(temp_dir)
        if not isinstance(raw_path, str):
            msg = "temp_dir must be a text path"
            raise TypeError(msg)
        if not raw_path.strip():
            msg = "temp_dir must not be empty"
            raise ValueError(msg)
        if "\x00" in raw_path:
            msg = "temp_dir must not contain null bytes"
            raise ValueError(msg)
        path = Path(raw_path)
        if path_exists_and_not_dir(path):
            msg = "temp_dir must be a directory"
            raise ValueError(msg)
        if path_is_symlink(path) or path_has_symlink_ancestor(path):
            msg = "temp_dir must not traverse a symlink"
            raise ValueError(msg)
        return path

    def process_batch(
        self,
        items: list[Any],
        operation: BatchOperation | Callable[[Any], Any] | None = None,
        batch_size: int | None = None,
    ) -> list[Any]:
        """Process a batch of items."""
        _validate_process_batch_operation(operation)
        batch_size = self.batch_size if batch_size is None else batch_size
        validate_positive_int_setting(batch_size, "batch_size")

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
                except Exception:
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
        return parse_item(item)

    def _analyze_complexity(self, item: Rule) -> dict[str, Any]:
        return analyze_complexity(item)

    def _serialize_item(self, item: Any) -> str:
        return serialize_item(item)

    def _validate_item(self, item: Rule) -> bool:
        return validate_item(item)

    @overload
    def process_files(
        self,
        file_paths: list[Path],
        operations: BatchOperation,
        output_dir: str | PathLike[str] | None = None,
    ) -> BatchResult: ...

    @overload
    def process_files(
        self,
        file_paths: list[Path],
        operations: list[BatchOperation],
        output_dir: str | PathLike[str] | None = None,
    ) -> dict[BatchOperation, BatchResult]: ...

    def process_files(
        self,
        file_paths: list[Path],
        operations: list[BatchOperation] | BatchOperation,
        output_dir: str | PathLike[str] | None = None,
    ) -> dict[BatchOperation, BatchResult] | BatchResult:
        """Process multiple YARA files with one or more operations."""
        normalized_file_paths = [Path(path) for path in validate_file_path_sequence(file_paths)]
        # Support both single operation and list of operations
        if isinstance(operations, BatchOperation):
            return self._process_files_single(normalized_file_paths, operations, output_dir)

        normalized_operations = _validate_operation_list(operations)
        return process_files_multi(
            self,
            normalized_file_paths,
            normalized_operations,
            output_dir,
            file_timeout=self.file_timeout,
        )

    def _process_files_single(
        self,
        file_paths: list[Path],
        operation: BatchOperation,
        output_dir: str | PathLike[str] | None = None,
    ) -> BatchResult:
        """Process multiple YARA files with a single operation."""
        return process_files_single(
            self,
            file_paths,
            operation,
            output_dir,
            file_timeout=self.file_timeout,
        )

    def analyze_rules(self, rules: list[Rule]) -> list[dict[str, Any]]:
        """Analyze a batch of rules."""
        return self.process_batch(rules, BatchOperation.COMPLEXITY)

    def get_statistics(self) -> dict[str, Any]:
        """Get processing statistics."""
        attempted_items = self._stats["items_processed"] + self._stats["failures"]
        return {
            **self._stats,
            "avg_batch_size": (
                attempted_items / self._stats["batches_processed"]
                if self._stats["batches_processed"] > 0
                else 0
            ),
            "failure_rate": (
                self._stats["failures"] / attempted_items * 100 if attempted_items > 0 else 0
            ),
        }

    @overload
    def process_directory(
        self,
        directory: Path,
        operations: BatchOperation,
        output_dir: str | PathLike[str] | None = None,
        file_pattern: FilePatterns = None,
        recursive: bool = False,
    ) -> BatchResult: ...

    @overload
    def process_directory(
        self,
        directory: Path,
        operations: list[BatchOperation],
        output_dir: str | PathLike[str] | None = None,
        file_pattern: FilePatterns = None,
        recursive: bool = False,
    ) -> dict[BatchOperation, BatchResult]: ...

    def process_directory(
        self,
        directory: Path,
        operations: list[BatchOperation] | BatchOperation,
        output_dir: str | PathLike[str] | None = None,
        file_pattern: FilePatterns = None,
        recursive: bool = False,
    ) -> dict[BatchOperation, BatchResult] | BatchResult:
        """Process all YARA files in a directory."""
        file_paths = list(iter_matching_files(directory, file_pattern, recursive))

        # Process using process_files
        return self.process_files(file_paths, operations, output_dir)

    def process_large_file(
        self,
        file_path: Path,
        operations: list[BatchOperation],
        output_dir: str | PathLike[str],
        split_rules: bool = False,
    ) -> dict[BatchOperation, BatchResult]:
        """Process a large YARA file, optionally splitting rules."""
        normalized_operations = _validate_operation_list(operations)
        return process_large_file_ops(
            self,
            file_path,
            normalized_operations,
            output_dir,
            split_rules,
            file_timeout=self.file_timeout,
        )
