"""Unified parser for YARA, YARA-X, and YARA-L dialects.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from os import stat_result
from pathlib import Path
import re
import stat as stat_module

from yaraast.ast.base import YaraFile
from yaraast.config import DEFAULT_STREAMING_THRESHOLD_MB as _DEFAULT_STREAMING_THRESHOLD_MB
from yaraast.dialects import DialectRegistry, YaraDialect, detect_dialect
from yaraast.errors import YaraASTError
from yaraast.parser.parser import Parser as YaraParser
from yaraast.performance.streaming_parser import StreamingParser
from yaraast.yaral.ast_nodes import YaraLFile


def _require_text_file_path(file_path: object) -> Path:
    if not isinstance(file_path, str | Path):
        msg = "YARA file path must be a string or Path"
        raise TypeError(msg)
    if isinstance(file_path, str) and not file_path.strip():
        msg = "YARA file path must not be empty"
        raise ValueError(msg)
    return Path(file_path) if isinstance(file_path, str) else file_path


def _read_yara_file_text(file_path: Path) -> str:
    try:
        with open(file_path, encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def _stat_yara_file(file_path: Path, display_path: object) -> stat_result:
    try:
        return file_path.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"YARA file not found: {display_path}") from exc
    except PermissionError as exc:
        raise PermissionError(f"Permission denied reading file: {display_path}") from exc
    except OSError as exc:
        raise OSError(f"Error accessing file {display_path}: {exc}") from exc


class UnifiedParser:
    """Multi-dialect YARA parser with automatic dialect detection.

    Supports:
    - Standard YARA
    - YARA-X (VirusTotal's next-gen YARA)
    - YARA-L (Google Chronicle)

    Examples:
        >>> from yaraast.unified_parser import UnifiedParser
        >>> ast = UnifiedParser('rule test { condition: true }').parse()
        >>> len(ast.rules)
        1
        >>> ast.rules[0].name
        'test'
    """

    # Streaming threshold based on empirical benchmarks:
    #
    # Benchmark results (18 MB file, 11,331 rules):
    # - Traditional Parser: 10s, 612 MB memory
    # - StreamingParser:    17s, 422 MB memory (73% slower, 31% less memory)
    #
    # Conclusion: Traditional Parser is better for almost all cases.
    # StreamingParser only makes sense for:
    # - Files >100 MB (rare in YARA)
    # - Systems with <500 MB available RAM (very rare in 2025)
    # - Processing rules incrementally without storing full AST
    #
    # Default: Use Traditional Parser (set threshold very high)
    # To use StreamingParser: Set force_streaming=True explicitly
    DEFAULT_STREAMING_THRESHOLD_MB = _DEFAULT_STREAMING_THRESHOLD_MB

    def __init__(self, text: str, dialect: YaraDialect | None = None) -> None:
        """Initialize unified parser.

        Args:
            text: The rule text to parse
            dialect: Optional dialect to force (auto-detected if None)

        """
        if not isinstance(text, str):
            msg = "Parser text must be a string"
            raise TypeError(msg)
        self.text = text
        if dialect is None:
            self.dialect = detect_dialect(text)
        elif isinstance(dialect, YaraDialect):
            self.dialect = dialect
        else:
            msg = "Parser dialect must be a YaraDialect or None"
            raise TypeError(msg)

    def parse(self) -> YaraFile | YaraLFile:
        """Parse the input based on detected or specified dialect.

        Returns:
            AST representation appropriate for the dialect

        """
        factory = DialectRegistry.get_parser_factory(self.dialect)
        if factory:
            result: YaraFile | YaraLFile = factory(self.text)
            return result
        # Standard YARA (default fallback)
        return YaraParser(self.text).parse()

    def get_dialect(self) -> YaraDialect:
        """Get the detected or specified dialect."""
        return self.dialect

    @staticmethod
    def _strip_comments(line: str, in_multiline: bool) -> tuple[str | None, bool]:
        """Strip comments from a preamble line.

        Returns:
            A tuple of (stripped_line_or_None, still_in_multiline_comment).
            ``None`` means the entire line is inside a comment and should be skipped.
        """
        result: list[str] = []
        index = 0
        in_string = False
        escaped = False

        while index < len(line):
            if in_multiline:
                end = line.find("*/", index)
                if end == -1:
                    clean_line = "".join(result)
                    return (clean_line if clean_line.strip() else None), True
                index = end + 2
                in_multiline = False
                continue

            char = line[index]
            if in_string:
                result.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                index += 1
                continue

            if char == '"':
                result.append(char)
                in_string = True
                index += 1
                continue

            if line.startswith("/*", index):
                in_multiline = True
                index += 2
                continue

            if line.startswith("//", index):
                break

            result.append(char)
            index += 1

        clean_line = "".join(result)
        return (clean_line if clean_line.strip() else None), in_multiline

    @classmethod
    def _extract_preamble_source(cls, file_path: Path) -> str:
        """Extract source lines before the first real rule definition."""
        rule_start_pattern = re.compile(r"^(?:(?:private|global)\s+)*rule\b", re.IGNORECASE)
        preamble_lines: list[str] = []

        try:
            with open(file_path, encoding="utf-8") as f:
                in_multiline_comment = False

                for line in f:
                    clean_line, in_multiline_comment = cls._strip_comments(
                        line, in_multiline_comment
                    )
                    if clean_line is None:
                        continue

                    stripped = clean_line.strip()
                    if not stripped:
                        continue

                    # Stop at first rule definition (end of preamble)
                    if rule_start_pattern.match(stripped):
                        break

                    preamble_lines.append(
                        clean_line if clean_line.endswith(("\n", "\r")) else f"{clean_line}\n"
                    )

        except (OSError, UnicodeDecodeError):
            return ""

        return "".join(preamble_lines)

    @classmethod
    def _extract_preamble_ast_fast(cls, file_path: Path) -> YaraFile:
        """Parse top-level constructs before the first real rule definition."""
        preamble_source = cls._extract_preamble_source(file_path)
        if not preamble_source.strip():
            return YaraFile()

        return YaraParser(preamble_source).parse()

    @classmethod
    def parse_file(
        cls,
        file_path: str | Path,
        dialect: YaraDialect | None = None,
        force_streaming: bool = False,
        streaming_threshold_mb: int | None = None,
    ) -> YaraFile | YaraLFile:
        """Parse a file with automatic dialect detection.

        Uses traditional parser by default. StreamingParser activates for files
        >100 MB (configurable via streaming_threshold_mb).

        Args:
            file_path: Path to the YARA rule file
            dialect: Optional dialect to force (auto-detected if None)
            force_streaming: Force StreamingParser for memory-constrained environments
            streaming_threshold_mb: File size threshold in MB (default: 100)

        Returns:
            Parsed AST (YaraFile or YaraLFile depending on dialect)

        Raises:
            FileNotFoundError: If the file does not exist
            OSError: If there is an error accessing the file

        """
        file_path_obj = _require_text_file_path(file_path)
        file_stat = _stat_yara_file(file_path_obj, file_path)
        file_size = file_stat.st_size
        if stat_module.S_ISDIR(file_stat.st_mode):
            msg = "YARA file path must not be a directory"
            raise IsADirectoryError(msg)

        # Use provided threshold or fall back to class default (100 MB)
        if streaming_threshold_mb is None:
            streaming_threshold_mb = cls.DEFAULT_STREAMING_THRESHOLD_MB
        if not isinstance(force_streaming, bool):
            msg = "force_streaming must be a boolean"
            raise TypeError(msg)
        if isinstance(streaming_threshold_mb, bool) or not isinstance(streaming_threshold_mb, int):
            msg = "streaming_threshold_mb must be a non-negative integer"
            raise TypeError(msg)
        if streaming_threshold_mb < 0:
            msg = "streaming_threshold_mb must be a non-negative integer"
            raise ValueError(msg)

        size_threshold_bytes = streaming_threshold_mb * 1024 * 1024

        # Auto-detect if we should use streaming parser based on file size
        # Note: Default threshold is 100 MB, so Traditional Parser is used for most files
        use_streaming = force_streaming or (file_size > size_threshold_bytes)

        if use_streaming:
            return cls._parse_file_streaming(file_path_obj, dialect)

        # Use traditional parser for smaller files (below threshold)
        # This is faster for small files as it avoids streaming overhead
        content = _read_yara_file_text(file_path_obj)

        parser = cls(content, dialect)
        return parser.parse()

    @classmethod
    def _parse_file_streaming(
        cls,
        file_path_obj: Path,
        dialect: YaraDialect | None,
    ) -> YaraFile | YaraLFile:
        """Parse a file using the streaming parser for large YARA files.

        Falls back to traditional parsing for non-standard dialects since
        the streaming parser only supports standard YARA.
        """
        # Detect dialect before streaming — read a small sample for detection
        if dialect is None:
            detected = cls.detect_file_dialect(str(file_path_obj))
            if detected in (YaraDialect.YARA_L, YaraDialect.YARA_X):
                # Streaming parser only supports standard YARA;
                # fall through to traditional parser for other dialects
                content = _read_yara_file_text(file_path_obj)
                parser = cls(content, detected)
                return parser.parse()

        # Use StreamingParser for very large standard YARA files
        preamble_ast = cls._extract_preamble_ast_fast(file_path_obj)

        def _dialect_factory(text: str, dialect: YaraDialect | None) -> YaraFile | YaraLFile:
            return cls(text, dialect).parse()

        streaming_parser = StreamingParser(dialect_parser_factory=_dialect_factory)
        rules = list(streaming_parser.parse_file(file_path_obj))
        parse_errors = streaming_parser.get_statistics()["parse_errors"]
        if parse_errors:
            # The streaming parser drops rules it cannot parse and only records
            # the count in its statistics. The traditional parser raises on the
            # same malformed input, so surface the failure here instead of
            # silently returning a partial AST.
            msg = (
                f"Failed to parse {parse_errors} malformed rule(s) while streaming "
                f"{file_path_obj}"
            )
            raise YaraASTError(msg)
        preamble_ast.rules = rules
        return preamble_ast

    @classmethod
    def detect_file_dialect(cls, file_path: str | Path) -> YaraDialect:
        """Detect the dialect of a file.

        Args:
            file_path: Path to the YARA rule file

        Returns:
            Detected dialect

        """
        file_path_obj = _require_text_file_path(file_path)
        file_stat = _stat_yara_file(file_path_obj, file_path)
        if stat_module.S_ISDIR(file_stat.st_mode):
            msg = "YARA file path must not be a directory"
            raise IsADirectoryError(msg)
        content = _read_yara_file_text(file_path_obj)

        return detect_dialect(content)
