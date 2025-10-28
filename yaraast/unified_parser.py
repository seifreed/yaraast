"""Unified parser for YARA, YARA-X, and YARA-L dialects.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

import re
from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Include
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.parser.parser import Parser as YaraParser
from yaraast.performance.streaming_parser import StreamingParser
from yaraast.yaral.ast_nodes import YaraLFile
from yaraast.yaral.parser import YaraLParser


class UnifiedParser:
    """Unified parser that automatically detects and parses different YARA dialects.

    Supports:
    - Standard YARA
    - YARA-X (VirusTotal's next-gen YARA)
    - YARA-L (Google Chronicle)
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
    DEFAULT_STREAMING_THRESHOLD_MB = 100  # Only for very large files

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
        if self.dialect == YaraDialect.YARA_L:
            parser = YaraLParser(self.text)
            return parser.parse()
        if self.dialect == YaraDialect.YARA_X:
            # For now, use standard YARA parser with extensions
            # Future: Add YARA-X specific parser extensions for new syntax features
            parser = YaraParser(self.text)
            return parser.parse()
        # Standard YARA
        parser = YaraParser(self.text)
        return parser.parse()

    def get_dialect(self) -> YaraDialect:
        """Get the detected or specified dialect."""
        return self.dialect

    @classmethod
    def _extract_preamble_fast(cls, file_path: Path) -> tuple[list[Import], list[Include]]:
        """Fast extraction of imports and includes without full parsing.

        Reads only the file preamble (before first rule) and extracts
        import/include statements using lightweight regex-based parsing.
        This provides O(k) performance where k is the number of preamble lines
        (typically <50), avoiding the need to parse the entire file.

        Supports:
        - Standard imports: import "pe"
        - Aliased imports: import "pe" as windows
        - Include statements: include "rules.yar"
        - Handles comments (// and /* */)
        - Handles whitespace variations

        Args:
            file_path: Path to YARA file

        Returns:
            Tuple of (imports, includes) lists. Returns empty lists on error
            to ensure graceful degradation if preamble parsing fails.

        Performance: O(k) where k is number of import/include lines

        Copyright (c) Marc Rivero López
        Licensed under GPLv3
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
                    if "/*" in line:
                        in_multiline_comment = True
                    if in_multiline_comment:
                        if "*/" in line:
                            in_multiline_comment = False
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

        By default, uses Traditional Parser which is faster and better for most cases.
        StreamingParser is available but only recommended for very large files (100+ MB)
        or when memory is extremely limited (<500 MB available).

        Performance (18 MB file benchmark):
        - Traditional Parser: 10s, 612 MB (RECOMMENDED - default)
        - StreamingParser:    17s, 422 MB (73% slower, 31% less memory)

        Args:
            file_path: Path to the YARA rule file (str or Path object)
            dialect: Optional dialect to force (auto-detected if None)
            force_streaming: Set to True to explicitly use StreamingParser.
                           Only recommended for files >100 MB or severe memory constraints.
            streaming_threshold_mb: File size threshold in MB for auto-streaming
                                   (default: 100 MB). Files larger than this will
                                   automatically use StreamingParser. Set to None
                                   to use DEFAULT_STREAMING_THRESHOLD_MB (100 MB).

        Returns:
            Parsed AST (YaraFile or YaraLFile depending on dialect)

        Raises:
            FileNotFoundError: If the file does not exist
            PermissionError: If the file cannot be read due to permissions
            OSError: If there is an error accessing the file

        Examples:
            # Normal usage (uses Traditional Parser for best performance)
            >>> ast = UnifiedParser.parse_file("rules.yar")

            # Explicit streaming for very large files
            >>> ast = UnifiedParser.parse_file("huge.yar", force_streaming=True)

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
            # Use StreamingParser for very large files (>100 MB by default)
            # Trade-off: ~70% slower but ~30% less memory
            # Only beneficial when memory is severely constrained

            # Extract imports/includes BEFORE streaming parse
            # This is a fast O(k) operation where k = number of preamble lines
            # Typically completes in <1ms even for files with hundreds of imports
            imports, includes = cls._extract_preamble_fast(file_path_obj)

            # Parse rules with streaming
            streaming_parser = StreamingParser()
            rules = list(streaming_parser.parse_file(file_path_obj))

            # Return complete YaraFile with all components
            # Now includes imports/includes that were previously lost
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
