"""Shared pragma scope validation helpers."""

from __future__ import annotations

from yaraast.ast.pragmas import PragmaScope
from yaraast.errors import SerializationError


def serialize_pragma_scope(scope: object, context: str = "Pragma") -> str:
    """Validate AST pragma scope before writing serialized output."""
    if isinstance(scope, PragmaScope):
        return scope.value
    if isinstance(scope, str):
        return deserialize_pragma_scope(scope, context).value
    msg = f"{context} scope must be a string"
    raise SerializationError(msg)


def deserialize_pragma_scope(value: object, context: str = "Pragma") -> PragmaScope:
    """Validate serialized pragma scope text."""
    if value is None:
        return PragmaScope.FILE
    if not isinstance(value, str):
        msg = f"{context} scope must be a string"
        raise SerializationError(msg)
    try:
        return PragmaScope(value)
    except ValueError as exc:
        msg = f"{context} scope must be a valid pragma scope"
        raise SerializationError(msg) from exc
