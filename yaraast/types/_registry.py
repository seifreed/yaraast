"""Type registry and core type definitions."""

from __future__ import annotations

from ._registry_base import YaraType
from ._registry_builtins import (
    BUILTIN_BOOL_FUNCTIONS,
    BUILTIN_DOUBLE_FUNCTIONS,
    BUILTIN_INT_FUNCTIONS_1ARG,
    BUILTIN_STRING_FUNCTIONS,
)
from ._registry_collections import ArrayType, DictionaryType, StringSetType, StructType
from ._registry_module import FunctionType, ModuleType, TypeSystem
from ._registry_primitives import (
    AnyType,
    BooleanType,
    DoubleType,
    FloatType,
    IntegerType,
    RangeType,
    RegexType,
    StringIdentifierType,
    StringType,
    UnknownType,
)
from .type_environment import TypeEnvironment

__all__ = [
    "BUILTIN_BOOL_FUNCTIONS",
    "BUILTIN_DOUBLE_FUNCTIONS",
    "BUILTIN_INT_FUNCTIONS_1ARG",
    "BUILTIN_STRING_FUNCTIONS",
    "AnyType",
    "ArrayType",
    "BooleanType",
    "DictionaryType",
    "DoubleType",
    "FloatType",
    "FunctionType",
    "IntegerType",
    "ModuleType",
    "RangeType",
    "RegexType",
    "StringIdentifierType",
    "StringSetType",
    "StringType",
    "StructType",
    "TypeEnvironment",
    "TypeSystem",
    "UnknownType",
    "YaraType",
]


def _init_static_types() -> None:
    """Initialize static type instances on YaraType class."""
    YaraType.INTEGER = IntegerType()
    YaraType.STRING = StringType()
    YaraType.BOOLEAN = BooleanType()
    YaraType.DOUBLE = DoubleType()
    YaraType.REGEX = RegexType()
    YaraType.UNKNOWN = UnknownType()


_init_static_types()
