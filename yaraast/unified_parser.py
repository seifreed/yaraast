"""Unified parser for YARA, YARA-X, and YARA-L dialects."""

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.parser.parser import Parser as YaraParser
from yaraast.yaral.ast_nodes import YaraLFile
from yaraast.yaral.parser import YaraLParser


class UnifiedParser:
    """Unified parser that automatically detects and parses different YARA dialects.

    Supports:
    - Standard YARA
    - YARA-X (VirusTotal's next-gen YARA)
    - YARA-L (Google Chronicle)
    """

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
    def parse_file(cls, file_path: str, dialect: YaraDialect = None) -> Any:
        """Parse a file with automatic dialect detection.

        Args:
            file_path: Path to the YARA rule file
            dialect: Optional dialect to force

        Returns:
            Parsed AST

        """
        with open(file_path, encoding="utf-8") as f:
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
