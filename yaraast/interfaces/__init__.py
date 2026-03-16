"""Interfaces module for dependency injection.

This module defines Protocol interfaces that enable dependency injection
and adherence to the Dependency Inversion Principle.
"""

from yaraast.interfaces.lexer_interface import ILexer
from yaraast.interfaces.token_interface import IToken

__all__ = ["ILexer", "IToken"]
