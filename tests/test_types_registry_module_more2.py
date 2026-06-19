"""Additional real coverage for types._registry_module."""

from __future__ import annotations

import builtins
from collections.abc import Callable
from types import ModuleType as PythonModuleType
from typing import Any, cast

import pytest

from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
from yaraast.types._registry_module import FunctionType, ModuleType, TypeSystem
from yaraast.types._registry_primitives import IntegerType, StringType
from yaraast.types.type_environment import TypeEnvironment

ImportFunction = Callable[[str, Any, Any, Any, int], PythonModuleType]


def test_type_system_builtin_module_fallback_initializes_pe_and_math() -> None:
    ts = TypeSystem()

    assert {"pe", "math"} <= set(ts.modules)

    pe = ts.get_module("pe")
    assert pe is not None
    assert isinstance(pe.attributes["machine"], IntegerType)
    assert isinstance(pe.attributes["number_of_sections"], IntegerType)
    assert isinstance(pe.attributes["is_pe"], IntegerType)
    assert isinstance(pe.attributes["version_info"], DictionaryType)
    assert isinstance(pe.attributes["sections"], ArrayType)

    section_struct = pe.attributes["sections"].element_type
    assert isinstance(section_struct, StructType)
    assert isinstance(section_struct.fields["name"], StringType)
    assert isinstance(section_struct.fields["virtual_address"], IntegerType)

    assert pe.functions["imphash"].parameters == []
    assert isinstance(pe.functions["imphash"].return_type, StringType)
    assert len(pe.functions["section_index"].parameters) == 1
    assert len(pe.functions["imports"].parameters) == 3
    assert pe.functions["imports"].min_parameters == 1
    assert isinstance(pe.functions["exports"].return_type, IntegerType)
    assert isinstance(pe.functions["locale"].return_type, IntegerType)
    assert isinstance(pe.functions["rva_to_offset"].return_type, IntegerType)

    math = ts.get_module("math")
    assert math is not None
    assert isinstance(math.functions["abs"].return_type, IntegerType)
    assert isinstance(math.functions["to_string"].return_type, StringType)
    assert "log" not in math.functions
    assert "sqrt" not in math.functions


def test_type_system_propagates_module_loader_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import: ImportFunction = builtins.__import__

    def fail_module_loader_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> PythonModuleType:
        if name == "yaraast.types.module_loader":
            raise ImportError("broken module loader", name="yaraast.types.module_loader")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_module_loader_import)

    with pytest.raises(ImportError, match="broken module loader"):
        TypeSystem()


def test_module_and_function_types_and_environment_aliases() -> None:
    ts = TypeSystem()
    assert ts.get_module("pe") is not None
    assert ts.get_module("math") is not None
    assert ts.get_module("missing") is None

    module = ModuleType(
        module_name="pe",
        attributes={"machine": IntegerType()},
    )
    assert str(module) == "module(pe)"
    assert module.is_compatible_with(ModuleType("pe", {})) is True
    assert module.is_compatible_with(ModuleType("math", {})) is False
    assert isinstance(module.get_attribute_type("machine"), IntegerType)
    assert module.get_attribute_type("missing") is None

    fn = FunctionType(
        name="abs",
        param_types=[IntegerType()],
        return_type=IntegerType(),
    )
    assert str(fn) == "abs(integer) -> integer"
    assert fn.is_compatible_with(IntegerType()) is False

    env = TypeEnvironment()
    env.push_scope()
    env.define("x", IntegerType())
    assert isinstance(env.lookup("x"), IntegerType)
    env.push_scope()
    env.define("y", StringType())
    assert isinstance(env.lookup("y"), StringType)
    env.pop_scope()
    assert env.lookup("y") is None
    env.pop_scope()
    env.pop_scope()

    env.add_module("pe")
    env.add_module("p", "pe")
    assert env.has_module("pe") is True
    assert env.has_module("p") is True
    assert env.get_module_name("p") == "pe"
    assert env.get_module_name("pe") == "pe"
    assert env.get_module_name("missing") is None

    env.add_string("$a")
    env.add_string("$abc")
    assert env.has_string("$a") is True
    assert env.has_string("$b") is False
    assert env.has_string_pattern("$a") is True
    assert env.has_string_pattern("$a*") is True
    assert env.has_string_pattern("$z*") is False

    env.add_rule("rule_a")
    assert env.has_rule("rule_a") is True
    assert env.has_rule("rule_b") is False


@pytest.mark.parametrize("attr", [None, 1, b"machine", object()])
def test_module_type_rejects_non_string_attribute_names(attr: Any) -> None:
    module = ModuleType("pe", {"machine": IntegerType()})

    with pytest.raises(TypeError, match="Module attribute name must be a string"):
        module.get_attribute_type(cast(str, attr))


@pytest.mark.parametrize("attr", ["", "   ", "\t"])
def test_module_type_rejects_empty_attribute_names(attr: str) -> None:
    module = ModuleType("pe", {"machine": IntegerType()})

    with pytest.raises(ValueError, match="Module attribute name cannot be empty"):
        module.get_attribute_type(attr)


@pytest.mark.parametrize("name", [None, 1, b"pe", object()])
def test_type_system_rejects_non_string_module_lookup_names(name: Any) -> None:
    ts = TypeSystem()

    with pytest.raises(TypeError, match="Module lookup name must be a string"):
        ts.get_module(cast(str, name))


@pytest.mark.parametrize("name", ["", "   ", "\t"])
def test_type_system_rejects_empty_module_lookup_names(name: str) -> None:
    ts = TypeSystem()

    with pytest.raises(ValueError, match="Module lookup name cannot be empty"):
        ts.get_module(name)


def test_type_environment_rejects_embedded_string_reference_operators() -> None:
    env = TypeEnvironment()

    with pytest.raises(ValueError, match="Invalid string reference '#a'"):
        env.add_string("#a")
    with pytest.raises(ValueError, match="Invalid string reference '@a'"):
        env.has_string("@a")
    with pytest.raises(ValueError, match="Invalid string reference '!a'"):
        env.has_string_pattern("!a")


@pytest.mark.parametrize("string_id", ["$", "$   "])
def test_type_environment_rejects_empty_or_whitespace_string_reference_body(
    string_id: str,
) -> None:
    env = TypeEnvironment()

    with pytest.raises(ValueError, match="Invalid string reference"):
        env.add_string(string_id)


@pytest.mark.parametrize("string_id", ["$a*", "a*", "$*", "*"])
def test_type_environment_rejects_wildcard_string_definitions(string_id: str) -> None:
    env = TypeEnvironment()

    with pytest.raises(ValueError, match="Invalid string reference"):
        env.add_string(string_id)


def test_type_environment_has_string_rejects_wildcard_lookup() -> None:
    env = TypeEnvironment()
    env.add_string("$a")

    with pytest.raises(ValueError, match="Invalid string reference"):
        env.has_string("$a*")
