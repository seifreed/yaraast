"""Shared helpers for semantic validators."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.types.type_environment import TypeEnvironment

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


KNOWN_MODULES: frozenset[str] = frozenset(
    {
        "pe",
        "elf",
        "math",
        "hash",
        "cuckoo",
        "dotnet",
        "time",
        "console",
        "string",
        "dex",
        "macho",
        "magic",
        "vt",
    }
)

BUILTIN_FUNCTION_ARITY: dict[str, tuple[int, int]] = {
    "uint8": (1, 1),
    "uint16": (1, 1),
    "uint32": (1, 1),
    "int8": (1, 1),
    "int16": (1, 1),
    "int32": (1, 1),
    "uint8be": (1, 1),
    "uint16be": (1, 1),
    "uint32be": (1, 1),
    "int8be": (1, 1),
    "int16be": (1, 1),
    "int32be": (1, 1),
    "uint16le": (1, 1),
    "uint32le": (1, 1),
    "int16le": (1, 1),
    "int32le": (1, 1),
}


def populate_env_for_file(ast: YaraFile, env: TypeEnvironment) -> None:
    """Populate a type environment with modules and strings from a file."""
    for imp in ast.imports:
        alias = imp.alias if imp.alias else imp.module
        env.add_module(alias, imp.module)

    for rule in ast.rules:
        populate_env_for_rule(rule, env)


def populate_env_for_rule(rule: Rule, env: TypeEnvironment) -> None:
    """Populate a type environment with strings from a rule."""
    for string_def in rule.strings:
        env.add_string(string_def.identifier)
