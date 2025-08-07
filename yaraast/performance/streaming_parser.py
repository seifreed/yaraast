"""Streaming parser for large YARA files."""

from __future__ import annotations

import mmap
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.parser import Parser

if TYPE_CHECKING:
    import io
    from collections.abc import Callable, Iterator

    from yaraast.ast.rules import Rule


class StreamingParser:
    """Parse large YARA files efficiently using streaming."""

    def __init__(
        self,
        buffer_size: int = 8192,
        max_memory_mb: int | None = None,
        enable_gc: bool = False,
        progress_callback: Callable | None = None,
    ) -> None:
        """Initialize streaming parser.

        Args:
            buffer_size: Size of read buffer in bytes
            max_memory_mb: Maximum memory usage in MB (ignored for compatibility)
            enable_gc: Enable garbage collection (ignored for compatibility)
            progress_callback: Progress callback function (ignored for compatibility)

        """
        self.buffer_size = buffer_size
        self.max_memory_mb = max_memory_mb
        self.enable_gc = enable_gc
        self.progress_callback = progress_callback
        self.parser = Parser()
        self._stats = {
            "rules_parsed": 0,
            "bytes_processed": 0,
            "parse_errors": 0,
            "peak_memory_mb": 0,
        }

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
        """Parse individual rules from a file."""
        from dataclasses import dataclass
        from enum import Enum

        class ParseStatus(Enum):
            SUCCESS = "success"
            ERROR = "error"

        @dataclass
        class ParseResult:
            file_path: str
            rule_name: str | None
            status: ParseStatus
            error: str | None
            parse_time: float
            rule_count: int
            import_count: int

        try:
            import time

            start_time = time.time()

            for rule in self.parse_file(file_path):
                parse_time = time.time() - start_time
                yield ParseResult(
                    file_path=str(file_path),
                    rule_name=rule.name if hasattr(rule, "name") else None,
                    status=ParseStatus.SUCCESS,
                    error=None,
                    parse_time=parse_time,
                    rule_count=1,
                    import_count=0,
                )
                start_time = time.time()
        except Exception as e:
            yield ParseResult(
                file_path=str(file_path),
                rule_name=None,
                status=ParseStatus.ERROR,
                error=str(e),
                parse_time=0,
                rule_count=0,
                import_count=0,
            )

    def parse_files(self, file_paths: list[Path]) -> Iterator[Any]:
        """Parse multiple files."""
        for file_path in file_paths:
            yield from self.parse_rules_from_file(file_path)

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
        """Cancel parsing (no-op for this implementation)."""
        # Implementation intentionally empty

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

    def _parse_mmap(
        self,
        mmapped_file: mmap.mmap,
        callback: Callable[[Rule], None] | None = None,
    ) -> Iterator[Rule]:
        """Parse memory-mapped file content."""
        # Find rule boundaries
        content = mmapped_file.read().decode("utf-8", errors="replace")
        mmapped_file.seek(0)  # Reset position

        # Simple rule extraction (can be optimized)
        import re

        rule_pattern = re.compile(r"rule\s+\w+[^{]*\{[^}]*\}", re.MULTILINE | re.DOTALL)

        for match in rule_pattern.finditer(content):
            rule_text = match.group(0)
            rule = self._parse_rule_text(rule_text)
            if rule:
                self._stats["rules_parsed"] += 1
                if callback:
                    callback(rule)
                yield rule

    def _parse_rule_text(self, rule_text: str) -> Rule | None:
        """Parse a single rule text."""
        try:
            # Create a minimal YARA file with just this rule
            yara_file = self.parser.parse(rule_text)
            if yara_file.rules:
                return yara_file.rules[0]
        except (ValueError, TypeError, AttributeError):
            self._stats["parse_errors"] += 1

        return None

    def reset_statistics(self) -> None:
        """Reset parsing statistics."""
        self._stats = {
            "rules_parsed": 0,
            "bytes_processed": 0,
            "parse_errors": 0,
        }

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
