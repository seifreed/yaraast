"""Streaming parser for large YARA files."""

from __future__ import annotations

import mmap
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.dialects import YaraDialect
from yaraast.parser.parser import Parser
from yaraast.performance.streaming_mmap import iter_rule_texts_from_mmap
from yaraast.performance.streaming_result_builders import (
    build_error_parse_result,
    build_file_parse_result,
    build_rule_parse_result,
    default_streaming_stats,
    timed_now,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    import io

    from yaraast.ast.rules import Rule


class StreamingParser:
    """Parse large YARA files efficiently using streaming."""

    def __init__(
        self,
        buffer_size: int = 8192,
        max_memory_mb: int | None = None,
        enable_gc: bool = False,
        progress_callback: Callable | None = None,
        dialect: YaraDialect | None = None,
        dialect_parser_factory: Callable | None = None,
    ) -> None:
        """Initialize streaming parser.

        Args:
            buffer_size: Size of read buffer in bytes
            max_memory_mb: Maximum memory usage in MB
            enable_gc: Enable garbage collection between files
            progress_callback: Progress callback function
            dialect: YARA dialect to use (auto-detects if None)
            dialect_parser_factory: Optional factory(text, dialect) -> YaraFile
                for parsing non-standard dialects without circular imports

        """
        self.buffer_size = buffer_size
        self.max_memory_mb = max_memory_mb
        self.enable_gc = enable_gc
        self.progress_callback = progress_callback
        self.dialect = dialect
        self._dialect_parser_factory = dialect_parser_factory
        self.parser = Parser()
        self._cancelled = False
        self._stats = default_streaming_stats()

    def parse_file(
        self,
        file_path: str | Path,
        callback: Callable[[Rule], None] | None = None,
    ) -> Iterator[Rule]:
        """Parse a YARA file in streaming fashion.

        Args:
            file_path: Path to YARA file
            callback: Optional callback for each parsed rule

        Yields:
            Parsed rules one at a time

        """
        file_path = Path(file_path)

        with (
            open(file_path, "rb") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file,
        ):
            # Use memory mapping for large files
            yield from self._parse_mmap(mmapped_file, callback)

    def parse_stream(
        self,
        stream: io.IOBase,
        callback: Callable[[Rule], None] | None = None,
    ) -> Iterator[Rule]:
        """Parse a stream of YARA content.

        Args:
            stream: Input stream
            callback: Optional callback for each parsed rule

        Yields:
            Parsed rules one at a time

        """
        buffer = ""
        rule_buffer = []
        in_rule = False
        brace_count = 0

        while True:
            chunk = stream.read(self.buffer_size)
            if not chunk:
                break

            if isinstance(chunk, bytes):
                chunk = chunk.decode("utf-8", errors="replace")

            buffer += chunk
            self._stats["bytes_processed"] += len(chunk)

            # Process lines
            lines = buffer.split("\n")
            buffer = lines[-1]  # Keep incomplete line

            for line in lines[:-1]:
                stripped = line.strip()

                # Track rule boundaries
                if stripped.startswith("rule ") and not in_rule:
                    in_rule = True
                    rule_buffer = [line]
                    brace_count = line.count("{") - line.count("}")
                elif in_rule:
                    rule_buffer.append(line)
                    brace_count += line.count("{") - line.count("}")

                    # Complete rule found
                    if brace_count == 0 and "}" in line:
                        rule_text = "\n".join(rule_buffer)
                        rule = self._parse_rule_text(rule_text)
                        if rule:
                            self._stats["rules_parsed"] += 1
                            if callback:
                                callback(rule)
                            yield rule

                        in_rule = False
                        rule_buffer = []

        # Handle any remaining buffer
        if buffer and in_rule:
            rule_buffer.append(buffer)
            rule_text = "\n".join(rule_buffer)
            rule = self._parse_rule_text(rule_text)
            if rule:
                self._stats["rules_parsed"] += 1
                if callback:
                    callback(rule)
                yield rule

    def parse_file_chunked(
        self,
        file_path: str | Path,
        chunk_size: int = 100,
    ) -> Iterator[list[Rule]]:
        """Parse file and yield rules in chunks.

        Args:
            file_path: Path to YARA file
            chunk_size: Number of rules per chunk

        Yields:
            Lists of parsed rules

        """
        chunk = []

        for rule in self.parse_file(file_path):
            chunk.append(rule)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []

        # Yield remaining rules
        if chunk:
            yield chunk

    def parse_rules_from_file(self, file_path: Path) -> Iterator[Any]:
        """Parse individual rules from a file (yields one result per rule)."""
        try:
            start_time = timed_now()

            for rule in self.parse_file(file_path):
                if self._cancelled:
                    break

                parse_time = timed_now() - start_time
                yield build_rule_parse_result(file_path, rule, parse_time)
                start_time = timed_now()
        except Exception as e:
            yield build_error_parse_result(file_path, e)

    def parse_files(self, file_paths: list[Path]) -> Iterator[Any]:
        """Parse multiple files (yields one result per file)."""
        for idx, file_path in enumerate(file_paths, 1):
            if self._cancelled:
                break

            try:
                start_time = timed_now()
                content = Path(file_path).read_text()
                ast = self.parser.parse(content)
                parse_time = timed_now() - start_time

                self._stats["files_processed"] += 1
                self._stats["files_successful"] += 1
                self._stats["total_parse_time"] += parse_time
                self._stats["rules_parsed"] += len(ast.rules)

                # Call progress callback if provided
                if self.progress_callback:
                    self.progress_callback(idx, len(file_paths), str(file_path))

                yield build_file_parse_result(file_path, ast, parse_time)
            except Exception as e:
                self._stats["files_processed"] += 1
                self._stats["parse_errors"] += 1

                yield build_error_parse_result(file_path, e)
            finally:
                self._maybe_collect_garbage()

    def parse_directory(
        self,
        dir_path: Path,
        pattern: str = "*.yar",
        recursive: bool = False,
    ) -> Iterator[Any]:
        """Parse all files in a directory."""
        files = list(dir_path.rglob(pattern)) if recursive else list(dir_path.glob(pattern))

        yield from self.parse_files(files)

    def get_statistics(self) -> dict[str, Any]:
        """Get parser statistics."""
        return dict(self._stats)

    def cancel(self) -> None:
        """Cancel parsing."""
        self._cancelled = True

    def parse_with_progress(
        self,
        file_path: str | Path,
        progress_callback: Callable[[int, int], None],
    ) -> list[Rule]:
        """Parse file with progress reporting.

        Args:
            file_path: Path to YARA file
            progress_callback: Callback(bytes_processed, total_bytes)

        Returns:
            List of parsed rules

        """
        file_path = Path(file_path)
        file_size = file_path.stat().st_size
        rules = []

        def rule_callback(rule: Rule) -> None:
            rules.append(rule)
            progress_callback(self._stats["bytes_processed"], file_size)

        list(self.parse_file(file_path, rule_callback))
        return rules

    def _maybe_collect_garbage(self) -> None:
        """Run garbage collection based on configuration."""
        if self.enable_gc or self._memory_limit_exceeded():
            import gc

            gc.collect()

    def _memory_limit_exceeded(self) -> bool:
        """Check if current RSS exceeds the configured memory limit."""
        if self.max_memory_mb is None:
            return False
        try:
            import os

            import psutil

            process = psutil.Process(os.getpid())
            rss_mb = process.memory_info().rss / 1024 / 1024
            return rss_mb > self.max_memory_mb
        except Exception:
            return False

    def _parse_mmap(
        self,
        mmapped_file: mmap.mmap,
        callback: Callable[[Rule], None] | None = None,
    ) -> Iterator[Rule]:
        """Parse memory-mapped file content using proper tokenization.

        This method uses the Lexer to properly identify rule boundaries,
        avoiding issues with braces in strings, regexes, or comments.
        """
        for rule_text in iter_rule_texts_from_mmap(mmapped_file):
            rule = self._parse_rule_text(rule_text)
            if rule:
                self._stats["rules_parsed"] += 1
                if callback:
                    callback(rule)
                yield rule

    def _parse_rule_text(self, rule_text: str) -> Rule | None:
        """Parse a single rule text using the appropriate dialect parser."""
        try:
            dialect = self.dialect
            if dialect is not None and dialect != YaraDialect.YARA:
                if self._dialect_parser_factory is not None:
                    result = self._dialect_parser_factory(rule_text, dialect)
                    if hasattr(result, "rules") and result.rules:
                        return result.rules[0]
            else:
                # Use standard parser (default, fastest path)
                yara_file = self.parser.parse(rule_text)
                if yara_file.rules:
                    return yara_file.rules[0]
        except Exception:
            self._stats["parse_errors"] += 1

        return None

    def reset_statistics(self) -> None:
        """Reset parsing statistics."""
        self._stats = default_streaming_stats()

    def estimate_memory_usage(self, file_path: str | Path) -> dict[str, Any]:
        """Estimate memory usage for parsing a file.

        Args:
            file_path: Path to YARA file

        Returns:
            Memory usage estimates

        """
        file_path = Path(file_path)
        file_size = file_path.stat().st_size

        # Rough estimates based on experience
        estimated_ast_size = file_size * 3  # AST typically 3x file size
        estimated_peak = file_size * 5  # Peak during parsing

        return {
            "file_size_mb": file_size / 1024 / 1024,
            "estimated_ast_mb": estimated_ast_size / 1024 / 1024,
            "estimated_peak_mb": estimated_peak / 1024 / 1024,
            "streaming_buffer_mb": self.buffer_size / 1024 / 1024,
        }
