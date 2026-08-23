"""YARA AST - A Python library for parsing and manipulating YARA rules."""

from importlib.metadata import version

from yaraast.api import SourceEdit, format_canonical, generate, parse, parse_file, rewrite_lossless

__version__ = version("yaraast")

__all__ = [
    "SourceEdit",
    "__version__",
    "format_canonical",
    "generate",
    "parse",
    "parse_file",
    "rewrite_lossless",
]
