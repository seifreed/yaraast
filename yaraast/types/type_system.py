"""Type system implementation for YARA semantic validation."""

from __future__ import annotations

from ._inference import TypeInference
from ._registry import (
    BUILTIN_BOOL_FUNCTIONS,
    BUILTIN_DOUBLE_FUNCTIONS,
    BUILTIN_INT_FUNCTIONS_1ARG,
    BUILTIN_STRING_FUNCTIONS,
    AnyType,
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    FloatType,
    FunctionType,
    IntegerType,
    ModuleType,
    RangeType,
    RegexType,
    StringIdentifierType,
    StringSetType,
    StringType,
    StructType,
    TypeSystem,
    UnknownType,
    YaraType,
)
from ._validation import TypeChecker, TypeValidator
from .module_contracts import FunctionDefinition, ModuleDefinition
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
    "FunctionDefinition",
    "FunctionType",
    "IntegerType",
    "ModuleDefinition",
    "ModuleType",
    "RangeType",
    "RegexType",
    "StringIdentifierType",
    "StringSetType",
    "StringType",
    "StructType",
    "TypeChecker",
    "TypeEnvironment",
    "TypeInference",
    "TypeSystem",
    "TypeValidator",
    "UnknownType",
    "YaraType",
]
