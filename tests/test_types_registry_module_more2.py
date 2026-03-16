"""Additional real coverage for types._registry_module."""

from __future__ import annotations

from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
from yaraast.types._registry_module import FunctionType, ModuleType, TypeSystem
from yaraast.types._registry_primitives import BooleanType, DoubleType, IntegerType, StringType
from yaraast.types.type_environment import TypeEnvironment


def test_type_system_builtin_module_fallback_initializes_pe_and_math() -> None:
    ts = object.__new__(TypeSystem)
    ts.modules = {}

    TypeSystem._init_builtin_modules(ts)

    assert set(ts.modules) == {"pe", "math"}

    pe = ts.get_module("pe")
    assert pe is not None
    assert isinstance(pe.attributes["machine"], IntegerType)
    assert isinstance(pe.attributes["number_of_sections"], IntegerType)
    assert isinstance(pe.attributes["is_pe"], BooleanType)
    assert isinstance(pe.attributes["version_info"], DictionaryType)
    assert isinstance(pe.attributes["imports"], ArrayType)
    assert isinstance(pe.attributes["sections"], ArrayType)

    section_struct = pe.attributes["sections"].element_type
    assert isinstance(section_struct, StructType)
    assert isinstance(section_struct.fields["name"], StringType)
    assert isinstance(section_struct.fields["virtual_address"], IntegerType)

    assert pe.functions["imphash"].parameters == []
    assert isinstance(pe.functions["imphash"].return_type, StringType)
    assert len(pe.functions["section_index"].parameters) == 1
    assert len(pe.functions["imports"].parameters) == 2
    assert isinstance(pe.functions["locale"].return_type, BooleanType)
    assert isinstance(pe.functions["rva_to_offset"].return_type, IntegerType)

    math = ts.get_module("math")
    assert math is not None
    assert isinstance(math.functions["abs"].return_type, IntegerType)
    assert isinstance(math.functions["to_string"].return_type, StringType)
    assert isinstance(math.functions["log"].return_type, DoubleType)
    assert isinstance(math.functions["sqrt"].return_type, DoubleType)


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
