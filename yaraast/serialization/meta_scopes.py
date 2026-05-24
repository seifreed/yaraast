"""Shared meta scope validation helpers."""

from __future__ import annotations

from yaraast.ast.modifiers import MetaScope
from yaraast.errors import SerializationError


def serialize_meta_scope(scope: object) -> str:
    """Validate AST meta scope before writing serialized output."""
    if isinstance(scope, MetaScope):
        return scope.value
    if isinstance(scope, str):
        validated = deserialize_meta_scope(scope)
        if validated is not None:
            return validated
    msg = "Meta scope must be a string"
    raise SerializationError(msg)


def deserialize_meta_scope(scope: str | None) -> str | None:
    """Validate serialized meta scope text before constructing MetaEntry."""
    if scope is None:
        return None
    try:
        return MetaScope(scope).value
    except ValueError as exc:
        msg = "Meta scope must be public, private, or protected"
        raise SerializationError(msg) from exc
