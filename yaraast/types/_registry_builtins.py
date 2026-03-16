"""Builtin function sets for type inference."""

from __future__ import annotations

BUILTIN_INT_FUNCTIONS_1ARG: frozenset[str] = frozenset(
    {
        "uint8",
        "uint16",
        "uint32",
        "int8",
        "int16",
        "int32",
        "uint8be",
        "uint16be",
        "uint32be",
        "int8be",
        "int16be",
        "int32be",
        "uint16le",
        "uint32le",
        "int16le",
        "int32le",
    }
)

BUILTIN_STRING_FUNCTIONS: frozenset[str] = frozenset()
BUILTIN_BOOL_FUNCTIONS: frozenset[str] = frozenset()
BUILTIN_DOUBLE_FUNCTIONS: frozenset[str] = frozenset()
