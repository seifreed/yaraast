"""Streaming parser for large YARA files."""

from __future__ import annotations

import codecs
from collections.abc import Callable, Iterator
import mmap
from os import PathLike, fspath
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from yaraast.ast.rules import Rule
from yaraast.dialects import YaraDialect
from yaraast.errors import YaraASTError
from yaraast.parser.parser import Parser
from yaraast.parser.source import parse_yara_source
from yaraast.performance.streaming_mmap import (
    iter_rule_text_byte_spans_from_mmap,
    iter_rule_texts_from_text,
)
from yaraast.performance.streaming_result_builders import (
    build_error_parse_result,
    build_file_parse_result,
    build_rule_parse_result,
    default_streaming_stats,
    timed_now,
)
from yaraast.performance.validation import (
    validate_file_path_sequence,
    validate_positive_int_setting,
)
from yaraast.shared.file_patterns import FilePatterns, iter_matching_files

if TYPE_CHECKING:
    import io


def _validate_optional_callable(value: object, name: str) -> None:
    if value is not None and not callable(value):
        msg = f"{name} must be callable"
        raise TypeError(msg)


def _require_pathlike(value: object, name: str) -> Path:
    if isinstance(value, bytes) or not isinstance(value, str | PathLike):
        msg = f"{name} must be a string or path-like object"
        raise TypeError(msg)
    raw_path = fspath(value)
    if not isinstance(raw_path, str):
        msg = f"{name} must be a text path"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    return Path(raw_path)


def _require_file_path(value: object, name: str = "file_path") -> Path:
    path = _require_pathlike(value, name)
    if path.exists() and path.is_dir():
        msg = f"{name} must not be a directory"
        raise IsADirectoryError(msg)
    return path


def _read_yara_text_file(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def _require_directory_path(value: object, name: str = "dir_path") -> Path:
    path = _require_pathlike(value, name)
    if path.exists() and not path.is_dir():
        msg = f"{name} must be a directory"
        raise NotADirectoryError(msg)
    return path


class StreamingParser:
    """Parse large YARA files efficiently using streaming."""

    def __init__(
        self,
        buffer_size: int = 8192,
        max_memory_mb: int | None = None,
        enable_gc: bool = False,
        progress_callback: Callable[[int, int, str], None] | None = None,
        dialect: YaraDialect | None = None,
        dialect_parser_factory: Callable[[str, YaraDialect | None], Any] | None = None,
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
        validate_positive_int_setting(buffer_size, "buffer_size")

        if max_memory_mb is not None:
            validate_positive_int_setting(max_memory_mb, "max_memory_mb")
        if not isinstance(enable_gc, bool):
            msg = "enable_gc must be a boolean"
            raise TypeError(msg)
        _validate_optional_callable(progress_callback, "progress_callback")
        _validate_optional_callable(dialect_parser_factory, "dialect_parser_factory")

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
        _validate_optional_callable(callback, "callback")
        file_path = _require_file_path(file_path)
        if file_path.stat().st_size == 0:
            return

        with (
            open(file_path, "rb") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file,
        ):
            # Use memory mapping for large files
            yield from self._parse_mmap(mmapped_file, callback)
            self._stats["bytes_processed"] = file_path.stat().st_size

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
        _validate_optional_callable(callback, "callback")
        stream_read = getattr(stream, "read", None)
        if not callable(stream_read):
            msg = "stream must provide a callable read method"
            raise TypeError(msg)

        chunks: list[str] = []
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        read_bytes = False
        while True:
            chunk = stream_read(self.buffer_size)
            if chunk in ("", b""):
                break
            if not isinstance(chunk, str | bytes):
                msg = "stream.read() must return str or bytes"
                raise TypeError(msg)

            if isinstance(chunk, bytes):
                read_bytes = True
                self._stats["bytes_processed"] += len(chunk)
                chunk = decoder.decode(chunk, final=False)
            else:
                self._stats["bytes_processed"] += len(chunk)

            chunks.append(chunk)

        if read_bytes:
            tail = decoder.decode(b"", final=True)
            if tail:
                chunks.append(tail)

        content = "".join(chunks)
        emitted_rule = False
        for rule_text in iter_rule_texts_from_text(content):
            emitted_rule = True
            rule = self._parse_rule_text(rule_text)
            if rule is not None:
                self._stats["rules_parsed"] += 1
                if callback:
                    callback(rule)
                yield rule
        if not emitted_rule and "rule" in content:
            self._stats["parse_errors"] += 1

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
        validate_positive_int_setting(chunk_size, "chunk_size")

        chunk: list[Rule] = []

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
        except (OSError, UnicodeDecodeError, ValueError, YaraASTError) as e:
            yield build_error_parse_result(file_path, e)

    def parse_files(self, file_paths: list[Path]) -> Iterator[Any]:
        """Parse multiple files (yields one result per file)."""
        normalized_file_paths = validate_file_path_sequence(file_paths)
        for idx, file_path in enumerate(normalized_file_paths, 1):
            if self._cancelled:
                break

            try:
                start_time = timed_now()
                content = _read_yara_text_file(file_path)
                ast = self._parse_content(content)
                parse_time = timed_now() - start_time

                self._stats["files_processed"] += 1
                self._stats["files_successful"] += 1
                self._stats["total_parse_time"] += parse_time
                self._stats["rules_parsed"] += len(ast.rules)

                # Call progress callback if provided
                if self.progress_callback:
                    self.progress_callback(idx, len(normalized_file_paths), str(file_path))

                yield build_file_parse_result(file_path, ast, parse_time)
            except (OSError, UnicodeDecodeError, ValueError, YaraASTError) as e:
                self._stats["files_processed"] += 1
                self._stats["parse_errors"] += 1

                yield build_error_parse_result(file_path, e)
            finally:
                self._maybe_collect_garbage()

    def parse_directory(
        self,
        dir_path: str | Path,
        pattern: FilePatterns = None,
        recursive: bool = False,
    ) -> Iterator[Any]:
        """Parse all files in a directory."""
        if not isinstance(recursive, bool):
            msg = "recursive must be a boolean"
            raise TypeError(msg)

        dir_path = _require_directory_path(dir_path)
        files = list(iter_matching_files(dir_path, pattern, recursive))

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
        if not callable(progress_callback):
            msg = "progress_callback must be callable"
            raise TypeError(msg)

        file_path = _require_file_path(file_path)
        file_size = file_path.stat().st_size
        rules: list[Rule] = []

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
        except ImportError:
            return False

        try:
            process = psutil.Process(os.getpid())
            rss_mb = process.memory_info().rss / 1024 / 1024
            return bool(rss_mb > self.max_memory_mb)
        except (OSError, psutil.Error):
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
        file_size = mmapped_file.size()
        rule_iter = iter(iter_rule_text_byte_spans_from_mmap(mmapped_file))
        try:
            current = next(rule_iter)
        except StopIteration:
            self._stats["bytes_processed"] = file_size
            return

        for next_rule in rule_iter:
            rule_text, _, byte_end = current
            yield from self._parse_mmap_rule(rule_text, byte_end, callback)
            current = next_rule

        rule_text, _, _ = current
        yield from self._parse_mmap_rule(rule_text, file_size, callback)
        self._stats["bytes_processed"] = file_size

    def _parse_mmap_rule(
        self,
        rule_text: str,
        bytes_processed: int,
        callback: Callable[[Rule], None] | None,
    ) -> Iterator[Rule]:
        """Parse one mmap-extracted rule and update progress statistics."""
        self._stats["bytes_processed"] = bytes_processed
        rule = self._parse_rule_text(rule_text)
        if rule is not None:
            self._stats["rules_parsed"] += 1
            if callback:
                callback(rule)
            yield rule

    def _parse_rule_text(self, rule_text: str) -> Rule | None:
        """Parse a single rule text using the appropriate dialect parser."""
        try:
            yara_file = self._parse_content(rule_text)
            if yara_file.rules:
                return cast(Rule, yara_file.rules[0])
        except (ValueError, YaraASTError):
            self._stats["parse_errors"] += 1

        return None

    def _parse_content(self, content: str) -> Any:
        """Parse full content using the configured dialect or auto-detection."""
        if self.dialect is not None:
            if self.dialect != YaraDialect.YARA and self._dialect_parser_factory is not None:
                return self._dialect_parser_factory(content, self.dialect)
            if self.dialect == YaraDialect.YARA:
                return self.parser.parse(content)
        return parse_yara_source(content)

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
        file_path = _require_file_path(file_path)
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
