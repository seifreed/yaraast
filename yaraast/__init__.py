"""YARA AST - A Python library for parsing and manipulating YARA rules."""

from yaraast.builder import (
    ConditionBuilder,
    ExpressionBuilder,
    HexStringBuilder,
    RuleBuilder,
    YaraFileBuilder,
)
from yaraast.codegen import CodeGenerator
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.errors import (
    CodeGenError,
    EvaluationError,
    LexerError,
    ParseError,
    ResolutionError,
    SemanticError,
    SerializationError,
    ValidationError,
    YaraASTError,
)
from yaraast.interfaces import ILexer
from yaraast.lexer import Lexer
from yaraast.parser import Parser
from yaraast.parser.source import parse_source
from yaraast.version import (
    YARA_SYNTAX_VERSION,
    YARAAST_VERSION,
    YARAAST_VERSION_MAJOR,
    YARAAST_VERSION_MINOR,
    YARAAST_VERSION_PATCH,
    get_version_info,
    get_version_string,
)
from yaraast.visitor import ASTVisitor, BaseVisitor
from yaraast.yaral.ast_nodes import YaraLFile
from yaraast.yaral.parser import YaraLParser

__version__ = YARAAST_VERSION
__all__ = [
    "YARAAST_VERSION",
    "YARAAST_VERSION_MAJOR",
    "YARAAST_VERSION_MINOR",
    "YARAAST_VERSION_PATCH",
    "YARA_SYNTAX_VERSION",
    "ASTVisitor",
    "BaseVisitor",
    "CodeGenError",
    "CodeGenerator",
    "ConditionBuilder",
    "EvaluationError",
    "ExpressionBuilder",
    "HexStringBuilder",
    "ILexer",
    "Lexer",
    "LexerError",
    "ParseError",
    "Parser",
    "ResolutionError",
    "RuleBuilder",
    "SemanticError",
    "SerializationError",
    "ValidationError",
    "YaraASTError",
    "YaraDialect",
    "YaraFileBuilder",
    "YaraLFile",
    "YaraLParser",
    "detect_dialect",
    "get_version_info",
    "get_version_string",
    "parse_source",
]
