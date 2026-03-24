"""Unified error hierarchy for yaraast."""

from __future__ import annotations


class YaraASTError(Exception):
    """Base exception for all yaraast errors."""


class ParseError(YaraASTError):
    """Error during YARA rule parsing."""


class LexerError(YaraASTError):
    """Error during lexical analysis."""


class SemanticError(YaraASTError):
    """Error during semantic validation."""


class CodeGenError(YaraASTError):
    """Error during code generation."""


class EvaluationError(YaraASTError):
    """Error during rule evaluation."""


class ValidationError(YaraASTError):
    """Error during rule validation."""


class SerializationError(YaraASTError):
    """Error during AST serialization/deserialization."""


class ResolutionError(YaraASTError):
    """Error during include/import resolution."""
