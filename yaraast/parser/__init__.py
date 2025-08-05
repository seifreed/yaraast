"""YARA parser module."""

from yaraast.parser.better_parser import Parser as Parser  # Re-export with explicit type
from yaraast.parser.parser import ParserError as ParserError  # Re-export with explicit type

__all__ = ["Parser", "ParserError"]
