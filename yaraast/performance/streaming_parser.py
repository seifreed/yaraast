"""Streaming parser for processing huge YARA rule collections incrementally."""

import gc
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Union

from yaraast.ast.base import YaraFile
from yaraast.parser import Parser, ParserError


class ParseStatus(Enum):
    """Parse result status."""
    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class ParseResult:
    """Result of parsing a single YARA file or rule."""

    file_path: Optional[str] = None
    rule_name: Optional[str] = None
    ast: Optional[YaraFile] = None
    status: ParseStatus = ParseStatus.SUCCESS
    error: Optional[str] = None
    parse_time: float = 0.0
    memory_usage: int = 0  # Bytes
    rule_count: int = 0
    import_count: int = 0


class StreamingParser:
    """Incremental parser for processing huge YARA rule collections.

    This parser is designed for AST processing of large rule sets by:
    - Streaming files one at a time to minimize memory usage
    - Supporting rule-level and file-level iteration
    - Providing progress callbacks and cancellation
    - Handling parsing errors gracefully
    - Memory management with automatic cleanup
    """

    def __init__(self,
                 max_memory_mb: int = 500,
                 enable_gc: bool = True,
                 progress_callback: Optional[Callable[[int, int, str], None]] = None,
                 error_callback: Optional[Callable[[str, Exception], None]] = None):
        """Initialize streaming parser.

        Args:
            max_memory_mb: Maximum memory usage before triggering cleanup
            enable_gc: Enable garbage collection after each file
            progress_callback: Called with (current, total, current_file)
            error_callback: Called with (file_path, error) for parse errors
        """
        self.max_memory_mb = max_memory_mb
        self.enable_gc = enable_gc
        self.progress_callback = progress_callback
        self.error_callback = error_callback
        self._cancelled = False
        self._parser = Parser()

        # Statistics
        self.stats = {
            'files_processed': 0,
            'files_successful': 0,
            'files_failed': 0,
            'rules_parsed': 0,
            'total_parse_time': 0.0,
            'peak_memory_mb': 0
        }

    def cancel(self) -> None:
        """Cancel ongoing parsing operation."""
        self._cancelled = True

    def parse_files(self, file_paths: List[Union[str, Path]]) -> Iterator[ParseResult]:
        """Parse multiple YARA files incrementally.

        Args:
            file_paths: List of file paths to parse

        Yields:
            ParseResult for each file processed
        """
        total_files = len(file_paths)

        for i, file_path in enumerate(file_paths):
            if self._cancelled:
                break

            file_path = Path(file_path)

            # Progress callback
            if self.progress_callback:
                self.progress_callback(i + 1, total_files, str(file_path))

            # Parse single file
            result = self._parse_single_file(file_path)

            # Update statistics
            self._update_stats(result)

            # Memory management
            if self.enable_gc and i % 10 == 0:  # GC every 10 files
                self._check_memory_usage()

            yield result

    def parse_directory(self,
                       directory: Union[str, Path],
                       pattern: str = "*.yar",
                       recursive: bool = True) -> Iterator[ParseResult]:
        """Parse all YARA files in a directory.

        Args:
            directory: Directory to scan
            pattern: File pattern to match (e.g., "*.yar", "*.yara")
            recursive: Whether to scan subdirectories

        Yields:
            ParseResult for each file found and processed
        """
        directory = Path(directory)

        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory}")

        # Find all matching files
        if recursive:
            file_paths = list(directory.rglob(pattern))
        else:
            file_paths = list(directory.glob(pattern))

        # Filter to only YARA files
        yara_files = [f for f in file_paths if self._is_yara_file(f)]

        # Parse files incrementally
        yield from self.parse_files(yara_files)

    def parse_rules_from_file(self, file_path: Union[str, Path]) -> Iterator[ParseResult]:
        """Parse individual rules from a multi-rule YARA file.

        This method splits a file into individual rules and parses each separately,
        useful for very large files with many rules.

        Args:
            file_path: Path to YARA file

        Yields:
            ParseResult for each rule in the file
        """
        file_path = Path(file_path)

        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            yield ParseResult(
                file_path=str(file_path),
                status=ParseStatus.ERROR,
                error=f"Failed to read file: {e}"
            )
            return

        # Extract individual rules using regex
        rule_blocks = self._extract_rule_blocks(content)

        for i, (rule_name, rule_content) in enumerate(rule_blocks):
            if self._cancelled:
                break

            result = ParseResult(
                file_path=str(file_path),
                rule_name=rule_name
            )

            try:
                # Parse individual rule
                ast = self._parser.parse(rule_content)
                result.ast = ast
                result.status = ParseStatus.SUCCESS
                result.rule_count = len(ast.rules)
                result.import_count = len(ast.imports)

            except Exception as e:
                result.status = ParseStatus.ERROR
                result.error = str(e)

                if self.error_callback:
                    self.error_callback(f"{file_path}:{rule_name}", e)

            yield result

    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics."""
        return self.stats.copy()

    def _parse_single_file(self, file_path: Path) -> ParseResult:
        """Parse a single YARA file."""
        import os
        import time

        import psutil

        result = ParseResult(file_path=str(file_path))
        start_time = time.time()
        process = psutil.Process(os.getpid())
        start_memory = process.memory_info().rss

        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > 100 * 1024 * 1024:  # 100MB
                result.status = ParseStatus.SKIPPED
                result.error = f"File too large: {file_size / 1024 / 1024:.1f}MB"
                return result

            # Read and parse file
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            ast = self._parser.parse(content)

            result.ast = ast
            result.status = ParseStatus.SUCCESS
            result.rule_count = len(ast.rules)
            result.import_count = len(ast.imports)

        except Exception as e:
            result.status = ParseStatus.ERROR
            result.error = str(e)

            if self.error_callback:
                self.error_callback(str(file_path), e)

        finally:
            # Calculate metrics
            result.parse_time = time.time() - start_time
            end_memory = process.memory_info().rss
            result.memory_usage = end_memory - start_memory

        return result

    def _extract_rule_blocks(self, content: str) -> List[tuple]:
        """Extract individual rule blocks from YARA content.

        Returns:
            List of (rule_name, rule_content) tuples
        """
        rule_blocks = []

        # Find all imports first
        import_lines = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('import ') or line.startswith('include '):
                import_lines.append(line)

        imports_text = '\n'.join(import_lines) + '\n\n' if import_lines else ''

        # Regex to find rule blocks
        rule_pattern = r'((?:private\s+|global\s+)*rule\s+(\w+)(?:\s*:\s*[\w\s]+)?\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\})'

        for match in re.finditer(rule_pattern, content, re.MULTILINE | re.DOTALL):
            rule_content = match.group(1)
            rule_name = match.group(2)

            # Combine imports with rule
            full_rule = imports_text + rule_content
            rule_blocks.append((rule_name, full_rule))

        return rule_blocks

    def _is_yara_file(self, file_path: Path) -> bool:
        """Check if file appears to be a YARA file."""
        if not file_path.is_file():
            return False

        # Check extension
        if file_path.suffix.lower() in ['.yar', '.yara', '.rule']:
            return True

        # Check content (first few lines)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = f.read(1024).lower()
                return any(keyword in first_lines for keyword in
                          ['rule ', 'import ', 'condition:', 'strings:', 'meta:'])
        except:
            return False

    def _update_stats(self, result: ParseResult) -> None:
        """Update parsing statistics."""
        self.stats['files_processed'] += 1

        if result.status == ParseStatus.SUCCESS:
            self.stats['files_successful'] += 1
            self.stats['rules_parsed'] += result.rule_count
        elif result.status == ParseStatus.ERROR:
            self.stats['files_failed'] += 1

        self.stats['total_parse_time'] += result.parse_time

        # Update peak memory
        if result.memory_usage > 0:
            memory_mb = result.memory_usage / (1024 * 1024)
            self.stats['peak_memory_mb'] = max(self.stats['peak_memory_mb'], memory_mb)

    def _check_memory_usage(self) -> None:
        """Check memory usage and trigger cleanup if needed."""
        try:
            import os

            import psutil

            process = psutil.Process(os.getpid())
            memory_mb = process.memory_info().rss / (1024 * 1024)

            if memory_mb > self.max_memory_mb:
                # Force garbage collection
                gc.collect()

                # Update peak memory
                self.stats['peak_memory_mb'] = max(self.stats['peak_memory_mb'], memory_mb)

        except ImportError:
            # psutil not available, just run GC
            gc.collect()


class BatchFileProcessor:
    """Helper for processing YARA files in batches."""

    def __init__(self, batch_size: int = 100):
        """Initialize batch processor.

        Args:
            batch_size: Number of files to process in each batch
        """
        self.batch_size = batch_size

    def process_in_batches(self,
                          file_paths: List[Union[str, Path]],
                          processor_func: Callable[[List[Path]], Any]) -> Iterator[Any]:
        """Process files in batches.

        Args:
            file_paths: List of file paths to process
            processor_func: Function that takes a batch of paths and returns results

        Yields:
            Results from each batch
        """
        file_paths = [Path(p) for p in file_paths]

        for i in range(0, len(file_paths), self.batch_size):
            batch = file_paths[i:i + self.batch_size]
            yield processor_func(batch)
