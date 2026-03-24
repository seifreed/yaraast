"""Unified parser for YARA, YARA-X, and YARA-L dialects.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

import re
from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Include
from yaraast.config import DEFAULT_STREAMING_THRESHOLD_MB as _DEFAULT_STREAMING_THRESHOLD_MB
from yaraast.dialects import DialectRegistry, YaraDialect, detect_dialect
from yaraast.parser.parser import Parser as YaraParser
from yaraast.performance.streaming_parser import StreamingParser
from yaraast.yaral.ast_nodes import YaraLFile


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

    def __init__(self, text: str, dialect: YaraDialect = None) -> None:
        """Initialize unified parser.

        Args:
            text: The rule text to parse
            dialect: Optional dialect to force (auto-detected if None)

        """
        self.text = text
        self.dialect = dialect or detect_dialect(text)

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

    @classmethod
    def _extract_preamble_fast(cls, file_path: Path) -> tuple[list[Import], list[Include]]:
        """Extract imports/includes from file preamble without full parsing.

        Reads lines before the first ``rule`` keyword using regex matching.
        O(k) where k is the number of preamble lines. Returns empty lists on error.
        """
        imports: list[Import] = []
        includes: list[Include] = []

        # Regex patterns for parsing
        # Match: import "module_name" [as alias]
        import_pattern = re.compile(r'^\s*import\s+"([^"]+)"(?:\s+as\s+(\w+))?\s*$')
        # Match: include "path/to/file.yar"
        include_pattern = re.compile(r'^\s*include\s+"([^"]+)"\s*$')

        try:
            with open(file_path, encoding="utf-8") as f:
                in_multiline_comment = False

                for line in f:
                    # Handle multi-line comments /* ... */
                    if in_multiline_comment:
                        if "*/" in line:
                            in_multiline_comment = False
                        continue
                    if "/*" in line:
                        in_multiline_comment = True
                        if "*/" not in line:
                            continue

                    # Remove single-line comments
                    if "//" in line:
                        line = line.split("//", 1)[0]

                    stripped = line.strip()

                    # Skip empty lines
                    if not stripped:
                        continue

                    # Stop at first rule definition
                    # This marks the end of the preamble section
                    if stripped.startswith("rule "):
                        break

                    # Try to match import statement
                    import_match = import_pattern.match(stripped)
                    if import_match:
                        module_name = import_match.group(1)
                        alias = import_match.group(2)  # May be None
                        imports.append(Import(module=module_name, alias=alias))
                        continue

                    # Try to match include statement
                    include_match = include_pattern.match(stripped)
                    if include_match:
                        include_path = include_match.group(1)
                        includes.append(Include(path=include_path))
                        continue

                    # If we encounter any other non-empty, non-comment line
                    # that's not import/include and not a rule, it might be
                    # a pragma or other directive - continue scanning
                    # (pragmas/extern/etc. don't affect import/include extraction)

        except (OSError, UnicodeDecodeError):
            # On any file reading error, return empty lists
            # This ensures streaming parser can still work, just without
            # import/include information
            return [], []

        return imports, includes

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
        # Normalize to Path early for consistent handling
        try:
            file_path_obj = Path(file_path) if isinstance(file_path, str) else file_path
            file_size = file_path_obj.stat().st_size
        except FileNotFoundError as e:
            raise FileNotFoundError(f"YARA file not found: {file_path}") from e
        except PermissionError as e:
            raise PermissionError(f"Permission denied reading file: {file_path}") from e
        except OSError as e:
            raise OSError(f"Error accessing file {file_path}: {e}") from e

        # Use provided threshold or fall back to class default (100 MB)
        if streaming_threshold_mb is None:
            streaming_threshold_mb = cls.DEFAULT_STREAMING_THRESHOLD_MB

        size_threshold_bytes = streaming_threshold_mb * 1024 * 1024

        # Auto-detect if we should use streaming parser based on file size
        # Note: Default threshold is 100 MB, so Traditional Parser is used for most files
        use_streaming = force_streaming or (file_size > size_threshold_bytes)

        if use_streaming:
            # Detect dialect before streaming — read a small sample for detection
            if dialect is None:
                detected = cls.detect_file_dialect(file_path_obj)
                if detected in (YaraDialect.YARA_L, YaraDialect.YARA_X):
                    # Streaming parser only supports standard YARA;
                    # fall through to traditional parser for other dialects
                    with open(file_path_obj, encoding="utf-8") as f:
                        content = f.read()
                    parser = cls(content, detected)
                    return parser.parse()

            # Use StreamingParser for very large standard YARA files
            imports, includes = cls._extract_preamble_fast(file_path_obj)

            def _dialect_factory(text, dialect):
                return cls(text, dialect).parse()

            streaming_parser = StreamingParser(dialect_parser_factory=_dialect_factory)
            rules = list(streaming_parser.parse_file(file_path_obj))
            return YaraFile(imports=imports, includes=includes, rules=rules)

        # Use traditional parser for smaller files (below threshold)
        # This is faster for small files as it avoids streaming overhead
        with open(file_path_obj, encoding="utf-8") as f:
            content = f.read()

        parser = cls(content, dialect)
        return parser.parse()

    @classmethod
    def detect_file_dialect(cls, file_path: str) -> YaraDialect:
        """Detect the dialect of a file.

        Args:
            file_path: Path to the YARA rule file

        Returns:
            Detected dialect

        """
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        return detect_dialect(content)
