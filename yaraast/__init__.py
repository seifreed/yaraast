"""YARA AST - A Python library for parsing and manipulating YARA rules."""

from importlib.metadata import version

from yaraast.api import (
    ParsedDocument,
    SourceEdit,
    format_canonical,
    generate,
    parse,
    parse_file,
    rewrite_lossless,
)
from yaraast.limits import CancellationToken, ResourceLimits

__version__ = version("yaraast")

__all__ = [
    "CancellationToken",
    "ParsedDocument",
    "ResourceLimits",
    "SourceEdit",
    "__version__",
    "format_canonical",
    "generate",
    "parse",
    "parse_file",
    "rewrite_lossless",
]
