"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Tests for YARA type system implementation.
"""

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import PlainString
from yaraast.types.type_system import (
    AnyType,
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    FloatType,
    FunctionDefinition,
    FunctionType,
    IntegerType,
    ModuleDefinition,
    ModuleType,
    RangeType,
    RegexType,
    StringIdentifierType,
    StringSetType,
    StringType,
    StructType,
    TypeChecker,
    TypeEnvironment,
    TypeInference,
    TypeSystem,
    TypeValidator,
    UnknownType,
    YaraType,
)


class TestIntegerType:
    """Tests for IntegerType class."""

    def test_integer_type_string_representation(self) -> None:
        """Test string representation of IntegerType."""
        int_type = IntegerType()
        assert str(int_type) == "integer"

    def test_integer_type_compatible_with_integer(self) -> None:
        """Test IntegerType is compatible with itself."""
        int_type = IntegerType()
        other_int = IntegerType()
        assert int_type.is_compatible_with(other_int) is True

    def test_integer_type_compatible_with_double(self) -> None:
        """Test IntegerType is compatible with DoubleType."""
        int_type = IntegerType()
        double_type = DoubleType()
        assert int_type.is_compatible_with(double_type) is True

    def test_integer_type_incompatible_with_string(self) -> None:
        """Test IntegerType is incompatible with StringType."""
        int_type = IntegerType()
        string_type = StringType()
        assert int_type.is_compatible_with(string_type) is False

    def test_integer_type_is_numeric(self) -> None:
        """Test IntegerType is recognized as numeric."""
        int_type = IntegerType()
        assert int_type.is_numeric() is True

    def test_integer_type_is_not_string_like(self) -> None:
        """Test IntegerType is not string-like."""
        int_type = IntegerType()
        assert int_type.is_string_like() is False


class TestDoubleType:
    """Tests for DoubleType class."""

    def test_double_type_string_representation(self) -> None:
        """Test string representation of DoubleType."""
        double_type = DoubleType()
        assert str(double_type) == "double"

    def test_double_type_compatible_with_double(self) -> None:
        """Test DoubleType is compatible with itself."""
        double_type1 = DoubleType()
        double_type2 = DoubleType()
        assert double_type1.is_compatible_with(double_type2) is True

    def test_double_type_compatible_with_integer(self) -> None:
        """Test DoubleType is compatible with IntegerType."""
        double_type = DoubleType()
        int_type = IntegerType()
        assert double_type.is_compatible_with(int_type) is True

    def test_double_type_incompatible_with_string(self) -> None:
        """Test DoubleType is incompatible with StringType."""
        double_type = DoubleType()
        string_type = StringType()
        assert double_type.is_compatible_with(string_type) is False

    def test_double_type_is_numeric(self) -> None:
        """Test DoubleType is recognized as numeric."""
        double_type = DoubleType()
        assert double_type.is_numeric() is True

    def test_double_type_is_not_string_like(self) -> None:
        """Test DoubleType is not string-like."""
        double_type = DoubleType()
        assert double_type.is_string_like() is False


class TestFloatType:
    """Tests for FloatType class."""

    def test_float_type_string_representation(self) -> None:
        """Test string representation of FloatType."""
        float_type = FloatType()
        assert str(float_type) == "float"

    def test_float_type_compatible_with_float(self) -> None:
        """Test FloatType is compatible with itself."""
        float_type1 = FloatType()
        float_type2 = FloatType()
        assert float_type1.is_compatible_with(float_type2) is True

    def test_float_type_compatible_with_double(self) -> None:
        """Test FloatType is compatible with DoubleType."""
        float_type = FloatType()
        double_type = DoubleType()
        assert float_type.is_compatible_with(double_type) is True

    def test_float_type_compatible_with_integer(self) -> None:
        """Test FloatType is compatible with IntegerType."""
        float_type = FloatType()
        int_type = IntegerType()
        assert float_type.is_compatible_with(int_type) is True

    def test_float_type_incompatible_with_string(self) -> None:
        """Test FloatType is incompatible with StringType."""
        float_type = FloatType()
        string_type = StringType()
        assert float_type.is_compatible_with(string_type) is False

    def test_float_type_is_numeric(self) -> None:
        """Test FloatType is recognized as numeric."""
        float_type = FloatType()
        assert float_type.is_numeric() is True


class TestStringType:
    """Tests for StringType class."""

    def test_string_type_string_representation(self) -> None:
        """Test string representation of StringType."""
        string_type = StringType()
        assert str(string_type) == "string"

    def test_string_type_compatible_with_string(self) -> None:
        """Test StringType is compatible with itself."""
        string_type1 = StringType()
        string_type2 = StringType()
        assert string_type1.is_compatible_with(string_type2) is True

    def test_string_type_incompatible_with_integer(self) -> None:
        """Test StringType is incompatible with IntegerType."""
        string_type = StringType()
        int_type = IntegerType()
        assert string_type.is_compatible_with(int_type) is False

    def test_string_type_is_not_numeric(self) -> None:
        """Test StringType is not numeric."""
        string_type = StringType()
        assert string_type.is_numeric() is False

    def test_string_type_is_string_like(self) -> None:
        """Test StringType is string-like."""
        string_type = StringType()
        assert string_type.is_string_like() is True


class TestBooleanType:
    """Tests for BooleanType class."""

    def test_boolean_type_string_representation(self) -> None:
        """Test string representation of BooleanType."""
        bool_type = BooleanType()
        assert str(bool_type) == "boolean"

    def test_boolean_type_compatible_with_boolean(self) -> None:
        """Test BooleanType is compatible with itself."""
        bool_type1 = BooleanType()
        bool_type2 = BooleanType()
        assert bool_type1.is_compatible_with(bool_type2) is True

    def test_boolean_type_incompatible_with_integer(self) -> None:
        """Test BooleanType is incompatible with IntegerType."""
        bool_type = BooleanType()
        int_type = IntegerType()
        assert bool_type.is_compatible_with(int_type) is False

    def test_boolean_type_is_not_numeric(self) -> None:
        """Test BooleanType is not numeric."""
        bool_type = BooleanType()
        assert bool_type.is_numeric() is False

    def test_boolean_type_is_not_string_like(self) -> None:
        """Test BooleanType is not string-like."""
        bool_type = BooleanType()
        assert bool_type.is_string_like() is False


class TestStringSetType:
    """Tests for StringSetType class."""

    def test_string_set_type_string_representation(self) -> None:
        """Test string representation of StringSetType."""
        set_type = StringSetType()
        assert str(set_type) == "string_set"

    def test_string_set_type_compatible_with_string_set(self) -> None:
        """Test StringSetType is compatible with itself."""
        set_type1 = StringSetType()
        set_type2 = StringSetType()
        assert set_type1.is_compatible_with(set_type2) is True

    def test_string_set_type_incompatible_with_string(self) -> None:
        """Test StringSetType is incompatible with StringType."""
        set_type = StringSetType()
        string_type = StringType()
        assert set_type.is_compatible_with(string_type) is False


class TestRangeType:
    """Tests for RangeType class."""

    def test_range_type_string_representation(self) -> None:
        """Test string representation of RangeType."""
        range_type = RangeType()
        assert str(range_type) == "range"

    def test_range_type_compatible_with_range(self) -> None:
        """Test RangeType is compatible with itself."""
        range_type1 = RangeType()
        range_type2 = RangeType()
        assert range_type1.is_compatible_with(range_type2) is True

    def test_range_type_incompatible_with_integer(self) -> None:
        """Test RangeType is incompatible with IntegerType."""
        range_type = RangeType()
        int_type = IntegerType()
        assert range_type.is_compatible_with(int_type) is False


class TestRegexType:
    """Tests for RegexType class."""

    def test_regex_type_string_representation(self) -> None:
        """Test string representation of RegexType."""
        regex_type = RegexType()
        assert str(regex_type) == "regex"

    def test_regex_type_compatible_with_regex(self) -> None:
        """Test RegexType is compatible with itself."""
        regex_type1 = RegexType()
        regex_type2 = RegexType()
        assert regex_type1.is_compatible_with(regex_type2) is True

    def test_regex_type_compatible_with_string(self) -> None:
        """Test RegexType is compatible with StringType."""
        regex_type = RegexType()
        string_type = StringType()
        assert regex_type.is_compatible_with(string_type) is True

    def test_regex_type_incompatible_with_integer(self) -> None:
        """Test RegexType is incompatible with IntegerType."""
        regex_type = RegexType()
        int_type = IntegerType()
        assert regex_type.is_compatible_with(int_type) is False

    def test_regex_type_is_string_like(self) -> None:
        """Test RegexType is string-like."""
        regex_type = RegexType()
        assert regex_type.is_string_like() is True


class TestStringIdentifierType:
    """Tests for StringIdentifierType class."""

    def test_string_identifier_type_string_representation(self) -> None:
        """Test string representation of StringIdentifierType."""
        str_id_type = StringIdentifierType()
        assert str(str_id_type) == "string_identifier"

    def test_string_identifier_type_compatible_with_string(self) -> None:
        """Test StringIdentifierType is compatible with StringType."""
        str_id_type = StringIdentifierType()
        string_type = StringType()
        assert str_id_type.is_compatible_with(string_type) is True

    def test_string_identifier_type_compatible_with_regex(self) -> None:
        """Test StringIdentifierType is compatible with RegexType."""
        str_id_type = StringIdentifierType()
        regex_type = RegexType()
        assert str_id_type.is_compatible_with(regex_type) is True

    def test_string_identifier_type_compatible_with_boolean(self) -> None:
        """Test StringIdentifierType is compatible with BooleanType."""
        str_id_type = StringIdentifierType()
        bool_type = BooleanType()
        assert str_id_type.is_compatible_with(bool_type) is True

    def test_string_identifier_type_compatible_with_itself(self) -> None:
        """Test StringIdentifierType is compatible with itself."""
        str_id_type1 = StringIdentifierType()
        str_id_type2 = StringIdentifierType()
        assert str_id_type1.is_compatible_with(str_id_type2) is True

    def test_string_identifier_type_incompatible_with_integer(self) -> None:
        """Test StringIdentifierType is incompatible with IntegerType."""
        str_id_type = StringIdentifierType()
        int_type = IntegerType()
        assert str_id_type.is_compatible_with(int_type) is False

    def test_string_identifier_type_is_string_like(self) -> None:
        """Test StringIdentifierType is string-like."""
        str_id_type = StringIdentifierType()
        assert str_id_type.is_string_like() is True


class TestUnknownType:
    """Tests for UnknownType class."""

    def test_unknown_type_string_representation(self) -> None:
        """Test string representation of UnknownType."""
        unknown_type = UnknownType()
        assert str(unknown_type) == "unknown"

    def test_unknown_type_compatible_with_any_type(self) -> None:
        """Test UnknownType is compatible with all types."""
        unknown_type = UnknownType()
        int_type = IntegerType()
        string_type = StringType()
        bool_type = BooleanType()

        assert unknown_type.is_compatible_with(int_type) is True
        assert unknown_type.is_compatible_with(string_type) is True
        assert unknown_type.is_compatible_with(bool_type) is True
        assert unknown_type.is_compatible_with(unknown_type) is True


class TestAnyType:
    """Tests for AnyType class."""

    def test_any_type_string_representation(self) -> None:
        """Test string representation of AnyType."""
        any_type = AnyType()
        assert str(any_type) == "any"

    def test_any_type_compatible_with_all_types(self) -> None:
        """Test AnyType is compatible with all types."""
        any_type = AnyType()
        int_type = IntegerType()
        string_type = StringType()
        bool_type = BooleanType()

        assert any_type.is_compatible_with(int_type) is True
        assert any_type.is_compatible_with(string_type) is True
        assert any_type.is_compatible_with(bool_type) is True
        assert any_type.is_compatible_with(any_type) is True


class TestModuleType:
    """Tests for ModuleType class."""

    def test_module_type_string_representation(self) -> None:
        """Test string representation of ModuleType."""
        module_type = ModuleType(module_name="pe", attributes={})
        assert str(module_type) == "module(pe)"

    def test_module_type_compatible_with_same_module(self) -> None:
        """Test ModuleType is compatible with same module name."""
        module1 = ModuleType(module_name="pe", attributes={})
        module2 = ModuleType(module_name="pe", attributes={})
        assert module1.is_compatible_with(module2) is True

    def test_module_type_incompatible_with_different_module(self) -> None:
        """Test ModuleType is incompatible with different module name."""
        module1 = ModuleType(module_name="pe", attributes={})
        module2 = ModuleType(module_name="elf", attributes={})
        assert module1.is_compatible_with(module2) is False

    def test_module_type_incompatible_with_non_module(self) -> None:
        """Test ModuleType is incompatible with non-module types."""
        module_type = ModuleType(module_name="pe", attributes={})
        int_type = IntegerType()
        assert module_type.is_compatible_with(int_type) is False

    def test_module_type_get_attribute_type_exists(self) -> None:
        """Test getting existing attribute type from module."""
        attributes = {"machine": IntegerType(), "is_dll": BooleanType()}
        module_type = ModuleType(module_name="pe", attributes=attributes)

        machine_type = module_type.get_attribute_type("machine")
        assert isinstance(machine_type, IntegerType)

        is_dll_type = module_type.get_attribute_type("is_dll")
        assert isinstance(is_dll_type, BooleanType)

    def test_module_type_get_attribute_type_not_exists(self) -> None:
        """Test getting non-existent attribute type from module."""
        attributes = {"machine": IntegerType()}
        module_type = ModuleType(module_name="pe", attributes=attributes)

        result = module_type.get_attribute_type("nonexistent")
        assert result is None


class TestArrayType:
    """Tests for ArrayType class."""

    def test_array_type_string_representation(self) -> None:
        """Test string representation of ArrayType."""
        array_type = ArrayType(element_type=IntegerType())
        assert str(array_type) == "array[integer]"

    def test_array_type_compatible_with_same_element_type(self) -> None:
        """Test ArrayType is compatible with same element type."""
        array1 = ArrayType(element_type=IntegerType())
        array2 = ArrayType(element_type=IntegerType())
        assert array1.is_compatible_with(array2) is True

    def test_array_type_compatible_with_compatible_element_type(self) -> None:
        """Test ArrayType is compatible when element types are compatible."""
        array_int = ArrayType(element_type=IntegerType())
        array_double = ArrayType(element_type=DoubleType())
        # IntegerType is compatible with DoubleType
        assert array_int.is_compatible_with(array_double) is True

    def test_array_type_incompatible_with_different_element_type(self) -> None:
        """Test ArrayType is incompatible with different element type."""
        array_int = ArrayType(element_type=IntegerType())
        array_str = ArrayType(element_type=StringType())
        assert array_int.is_compatible_with(array_str) is False

    def test_array_type_incompatible_with_non_array(self) -> None:
        """Test ArrayType is incompatible with non-array types."""
        array_type = ArrayType(element_type=IntegerType())
        int_type = IntegerType()
        assert array_type.is_compatible_with(int_type) is False


class TestDictionaryType:
    """Tests for DictionaryType class."""

    def test_dictionary_type_string_representation(self) -> None:
        """Test string representation of DictionaryType."""
        dict_type = DictionaryType(key_type=StringType(), value_type=IntegerType())
        assert str(dict_type) == "dict[string, integer]"

    def test_dictionary_type_compatible_with_same_types(self) -> None:
        """Test DictionaryType is compatible with same key and value types."""
        dict1 = DictionaryType(key_type=StringType(), value_type=IntegerType())
        dict2 = DictionaryType(key_type=StringType(), value_type=IntegerType())
        assert dict1.is_compatible_with(dict2) is True

    def test_dictionary_type_compatible_with_compatible_types(self) -> None:
        """Test DictionaryType is compatible when key and value types are compatible."""
        dict1 = DictionaryType(key_type=StringType(), value_type=IntegerType())
        dict2 = DictionaryType(key_type=StringType(), value_type=DoubleType())
        # IntegerType is compatible with DoubleType
        assert dict1.is_compatible_with(dict2) is True

    def test_dictionary_type_incompatible_with_different_key_type(self) -> None:
        """Test DictionaryType is incompatible with different key type."""
        dict1 = DictionaryType(key_type=StringType(), value_type=IntegerType())
        dict2 = DictionaryType(key_type=IntegerType(), value_type=IntegerType())
        assert dict1.is_compatible_with(dict2) is False

    def test_dictionary_type_incompatible_with_different_value_type(self) -> None:
        """Test DictionaryType is incompatible with different value type."""
        dict1 = DictionaryType(key_type=StringType(), value_type=IntegerType())
        dict2 = DictionaryType(key_type=StringType(), value_type=StringType())
        assert dict1.is_compatible_with(dict2) is False

    def test_dictionary_type_incompatible_with_non_dictionary(self) -> None:
        """Test DictionaryType is incompatible with non-dictionary types."""
        dict_type = DictionaryType(key_type=StringType(), value_type=IntegerType())
        int_type = IntegerType()
        assert dict_type.is_compatible_with(int_type) is False


class TestFunctionType:
    """Tests for FunctionType class."""

    def test_function_type_string_representation(self) -> None:
        """Test string representation of FunctionType."""
        func_type = FunctionType(
            name="test_func",
            param_types=[IntegerType(), StringType()],
            return_type=BooleanType(),
        )
        assert str(func_type) == "test_func(integer, string) -> boolean"

    def test_function_type_string_representation_no_params(self) -> None:
        """Test string representation of FunctionType with no parameters."""
        func_type = FunctionType(
            name="no_params",
            param_types=[],
            return_type=IntegerType(),
        )
        assert str(func_type) == "no_params() -> integer"

    def test_function_type_not_compatible_with_any_type(self) -> None:
        """Test FunctionType is not compatible with any type."""
        func_type = FunctionType(
            name="test_func",
            param_types=[IntegerType()],
            return_type=BooleanType(),
        )
        other_func = FunctionType(
            name="test_func",
            param_types=[IntegerType()],
            return_type=BooleanType(),
        )
        int_type = IntegerType()

        # Functions are not directly comparable
        assert func_type.is_compatible_with(other_func) is False
        assert func_type.is_compatible_with(int_type) is False


class TestStructType:
    """Tests for StructType class."""

    def test_struct_type_string_representation_empty(self) -> None:
        """Test string representation of empty StructType."""
        struct_type = StructType(fields={})
        assert str(struct_type) == "struct()"

    def test_struct_type_string_representation_with_fields(self) -> None:
        """Test string representation of StructType with fields."""
        fields = {"name": StringType(), "age": IntegerType()}
        struct_type = StructType(fields=fields)
        result = str(struct_type)

        # Field order may vary, so check both possibilities
        assert result in [
            "struct(name: string, age: integer)",
            "struct(age: integer, name: string)",
        ]

    def test_struct_type_compatible_with_same_fields(self) -> None:
        """Test StructType is compatible with same fields."""
        fields = {"name": StringType(), "age": IntegerType()}
        struct1 = StructType(fields=fields.copy())
        struct2 = StructType(fields=fields.copy())
        assert struct1.is_compatible_with(struct2) is True

    def test_struct_type_compatible_with_compatible_field_types(self) -> None:
        """Test StructType is compatible when field types are compatible."""
        fields1 = {"count": IntegerType()}
        fields2 = {"count": DoubleType()}
        struct1 = StructType(fields=fields1)
        struct2 = StructType(fields=fields2)
        # IntegerType is compatible with DoubleType
        assert struct1.is_compatible_with(struct2) is True

    def test_struct_type_incompatible_with_missing_fields(self) -> None:
        """Test StructType is incompatible when fields are missing."""
        fields1 = {"name": StringType(), "age": IntegerType()}
        fields2 = {"name": StringType()}
        struct1 = StructType(fields=fields1)
        struct2 = StructType(fields=fields2)
        assert struct1.is_compatible_with(struct2) is False

    def test_struct_type_incompatible_with_different_field_types(self) -> None:
        """Test StructType is incompatible with different field types."""
        fields1 = {"name": StringType()}
        fields2 = {"name": IntegerType()}
        struct1 = StructType(fields=fields1)
        struct2 = StructType(fields=fields2)
        assert struct1.is_compatible_with(struct2) is False

    def test_struct_type_incompatible_with_non_struct(self) -> None:
        """Test StructType is incompatible with non-struct types."""
        struct_type = StructType(fields={"name": StringType()})
        int_type = IntegerType()
        assert struct_type.is_compatible_with(int_type) is False


class TestFunctionDefinition:
    """Tests for FunctionDefinition class."""

    def test_function_definition_creation(self) -> None:
        """Test creating FunctionDefinition."""
        func_def = FunctionDefinition(
            name="test_func",
            return_type=IntegerType(),
            parameters=[("x", IntegerType()), ("y", StringType())],
        )
        assert func_def.name == "test_func"
        assert isinstance(func_def.return_type, IntegerType)
        assert len(func_def.parameters) == 2
        assert func_def.parameters[0] == ("x", IntegerType())
        assert func_def.parameters[1][0] == "y"
        assert isinstance(func_def.parameters[1][1], StringType)

    def test_function_definition_default_parameters(self) -> None:
        """Test FunctionDefinition with default empty parameters."""
        func_def = FunctionDefinition(name="no_params", return_type=BooleanType())
        assert func_def.name == "no_params"
        assert isinstance(func_def.return_type, BooleanType)
        assert func_def.parameters == []


class TestModuleDefinition:
    """Tests for ModuleDefinition class."""

    def test_module_definition_creation(self) -> None:
        """Test creating ModuleDefinition."""
        attributes = {"version": StringType(), "count": IntegerType()}
        functions = {
            "do_something": FunctionDefinition(
                name="do_something",
                return_type=BooleanType(),
            ),
        }
        constants = {"MAX_SIZE": IntegerType()}

        mod_def = ModuleDefinition(
            name="test_module",
            attributes=attributes,
            functions=functions,
            constants=constants,
        )

        assert mod_def.name == "test_module"
        assert len(mod_def.attributes) == 2
        assert isinstance(mod_def.attributes["version"], StringType)
        assert len(mod_def.functions) == 1
        assert "do_something" in mod_def.functions
        assert len(mod_def.constants) == 1

    def test_module_definition_default_values(self) -> None:
        """Test ModuleDefinition with default empty values."""
        mod_def = ModuleDefinition(name="empty_module")
        assert mod_def.name == "empty_module"
        assert mod_def.attributes == {}
        assert mod_def.functions == {}
        assert mod_def.constants == {}


class TestTypeEnvironment:
    """Tests for TypeEnvironment class."""

    def test_type_environment_initialization(self) -> None:
        """Test TypeEnvironment initializes with empty global scope."""
        env = TypeEnvironment()
        assert len(env.scopes) == 1
        assert len(env.scopes[0]) == 0
        assert len(env.modules) == 0
        assert len(env.strings) == 0
        assert len(env.rules) == 0

    def test_type_environment_push_pop_scope(self) -> None:
        """Test pushing and popping scopes."""
        env = TypeEnvironment()
        assert len(env.scopes) == 1

        env.push_scope()
        assert len(env.scopes) == 2

        env.push_scope()
        assert len(env.scopes) == 3

        env.pop_scope()
        assert len(env.scopes) == 2

        env.pop_scope()
        assert len(env.scopes) == 1

    def test_type_environment_cannot_pop_global_scope(self) -> None:
        """Test cannot pop global scope."""
        env = TypeEnvironment()
        env.pop_scope()
        # Global scope should remain
        assert len(env.scopes) == 1

    def test_type_environment_define_and_lookup(self) -> None:
        """Test defining and looking up variables."""
        env = TypeEnvironment()
        env.define("x", IntegerType())
        env.define("y", StringType())

        x_type = env.lookup("x")
        assert isinstance(x_type, IntegerType)

        y_type = env.lookup("y")
        assert isinstance(y_type, StringType)

    def test_type_environment_lookup_nonexistent(self) -> None:
        """Test looking up nonexistent variable."""
        env = TypeEnvironment()
        result = env.lookup("nonexistent")
        assert result is None

    def test_type_environment_scoped_lookup(self) -> None:
        """Test variable lookup through scopes."""
        env = TypeEnvironment()
        env.define("global_var", IntegerType())

        env.push_scope()
        env.define("local_var", StringType())

        # Should find both variables
        assert isinstance(env.lookup("global_var"), IntegerType)
        assert isinstance(env.lookup("local_var"), StringType)

        env.pop_scope()

        # Global var still accessible, local var not
        assert isinstance(env.lookup("global_var"), IntegerType)
        assert env.lookup("local_var") is None

    def test_type_environment_shadowing(self) -> None:
        """Test variable shadowing in nested scopes."""
        env = TypeEnvironment()
        env.define("x", IntegerType())

        env.push_scope()
        env.define("x", StringType())

        # Should get the shadowed version
        x_type = env.lookup("x")
        assert isinstance(x_type, StringType)

        env.pop_scope()

        # Should get the original version
        x_type = env.lookup("x")
        assert isinstance(x_type, IntegerType)

    def test_type_environment_add_module_without_alias(self) -> None:
        """Test adding module without alias."""
        env = TypeEnvironment()
        env.add_module("pe")

        assert env.has_module("pe") is True
        assert env.get_module_name("pe") == "pe"

    def test_type_environment_add_module_with_alias(self) -> None:
        """Test adding module with alias."""
        env = TypeEnvironment()
        env.add_module(alias="my_pe", module="pe")

        assert env.has_module("pe") is True
        assert env.has_module("my_pe") is True
        assert env.get_module_name("my_pe") == "pe"

    def test_type_environment_has_module_nonexistent(self) -> None:
        """Test checking for nonexistent module."""
        env = TypeEnvironment()
        assert env.has_module("nonexistent") is False

    def test_type_environment_get_module_name_nonexistent(self) -> None:
        """Test getting name of nonexistent module."""
        env = TypeEnvironment()
        result = env.get_module_name("nonexistent")
        assert result is None

    def test_type_environment_add_and_has_string(self) -> None:
        """Test adding and checking strings."""
        env = TypeEnvironment()
        env.add_string("$str1")
        env.add_string("$str2")

        assert env.has_string("$str1") is True
        assert env.has_string("$str2") is True
        assert env.has_string("$nonexistent") is False

    def test_type_environment_has_string_pattern_exact_match(self) -> None:
        """Test string pattern matching with exact match."""
        env = TypeEnvironment()
        env.add_string("$str1")

        assert env.has_string_pattern("$str1") is True
        assert env.has_string_pattern("$str2") is False

    def test_type_environment_has_string_pattern_wildcard(self) -> None:
        """Test string pattern matching with wildcard."""
        env = TypeEnvironment()
        env.add_string("$str1")
        env.add_string("$str2")
        env.add_string("$str123")
        env.add_string("$other")

        assert env.has_string_pattern("$str*") is True
        assert env.has_string_pattern("$str1*") is True
        assert env.has_string_pattern("$other*") is True
        assert env.has_string_pattern("$nonexistent*") is False

    def test_type_environment_add_and_has_rule(self) -> None:
        """Test adding and checking rules."""
        env = TypeEnvironment()
        env.add_rule("rule1")
        env.add_rule("rule2")

        assert env.has_rule("rule1") is True
        assert env.has_rule("rule2") is True
        assert env.has_rule("nonexistent") is False


class TestTypeSystem:
    """Tests for TypeSystem class."""

    def test_type_system_initialization(self) -> None:
        """Test TypeSystem initializes with modules."""
        type_sys = TypeSystem()
        assert isinstance(type_sys.modules, dict)
        # Should have at least some builtin modules
        assert len(type_sys.modules) > 0

    def test_type_system_has_pe_module(self) -> None:
        """Test TypeSystem has PE module."""
        type_sys = TypeSystem()
        pe_module = type_sys.get_module("pe")

        assert pe_module is not None
        assert pe_module.name == "pe"
        assert "machine" in pe_module.attributes
        assert "is_dll" in pe_module.attributes

    def test_type_system_has_math_module(self) -> None:
        """Test TypeSystem has math module."""
        type_sys = TypeSystem()
        math_module = type_sys.get_module("math")

        assert math_module is not None
        assert math_module.name == "math"
        assert "abs" in math_module.functions
        assert "min" in math_module.functions
        assert "max" in math_module.functions

    def test_type_system_get_nonexistent_module(self) -> None:
        """Test getting nonexistent module."""
        type_sys = TypeSystem()
        result = type_sys.get_module("nonexistent")
        assert result is None

    def test_type_system_pe_module_attributes(self) -> None:
        """Test PE module has expected attributes."""
        type_sys = TypeSystem()
        pe_module = type_sys.get_module("pe")

        assert pe_module is not None

        # Check integer attributes
        assert isinstance(pe_module.attributes["machine"], IntegerType)
        assert isinstance(pe_module.attributes["number_of_sections"], IntegerType)
        assert isinstance(pe_module.attributes["timestamp"], IntegerType)

        # Check boolean attributes
        assert isinstance(pe_module.attributes["is_dll"], BooleanType)
        assert isinstance(pe_module.attributes["is_32bit"], BooleanType)
        assert isinstance(pe_module.attributes["is_64bit"], BooleanType)

        # Check complex types
        assert isinstance(pe_module.attributes["sections"], ArrayType)
        assert isinstance(pe_module.attributes["version_info"], DictionaryType)

    def test_type_system_pe_module_functions(self) -> None:
        """Test PE module has expected functions."""
        type_sys = TypeSystem()
        pe_module = type_sys.get_module("pe")

        assert pe_module is not None
        assert "imphash" in pe_module.functions
        assert "section_index" in pe_module.functions
        assert "exports" in pe_module.functions
        assert "imports" in pe_module.functions

        # Check imphash function
        imphash_func = pe_module.functions["imphash"]
        assert isinstance(imphash_func.return_type, StringType)
        assert len(imphash_func.parameters) == 0

    def test_type_system_math_module_functions(self) -> None:
        """Test math module has expected functions."""
        type_sys = TypeSystem()
        math_module = type_sys.get_module("math")

        assert math_module is not None

        # Check abs function
        abs_func = math_module.functions["abs"]
        assert isinstance(abs_func.return_type, IntegerType)
        assert len(abs_func.parameters) == 1

        # Check min function
        min_func = math_module.functions["min"]
        assert isinstance(min_func.return_type, IntegerType)
        assert len(min_func.parameters) == 2

        # Check log function
        log_func = math_module.functions["log"]
        assert isinstance(log_func.return_type, DoubleType)


class TestYaraTypeStaticInstances:
    """Tests for static type instances on YaraType class."""

    def test_static_type_instances_exist(self) -> None:
        """Test that static type instances are initialized."""
        assert hasattr(YaraType, "INTEGER")
        assert hasattr(YaraType, "STRING")
        assert hasattr(YaraType, "BOOLEAN")
        assert hasattr(YaraType, "DOUBLE")
        assert hasattr(YaraType, "REGEX")
        assert hasattr(YaraType, "UNKNOWN")

    def test_static_integer_type(self) -> None:
        """Test static INTEGER type instance."""
        assert isinstance(YaraType.INTEGER, IntegerType)
        assert str(YaraType.INTEGER) == "integer"

    def test_static_string_type(self) -> None:
        """Test static STRING type instance."""
        assert isinstance(YaraType.STRING, StringType)
        assert str(YaraType.STRING) == "string"

    def test_static_boolean_type(self) -> None:
        """Test static BOOLEAN type instance."""
        assert isinstance(YaraType.BOOLEAN, BooleanType)
        assert str(YaraType.BOOLEAN) == "boolean"

    def test_static_double_type(self) -> None:
        """Test static DOUBLE type instance."""
        assert isinstance(YaraType.DOUBLE, DoubleType)
        assert str(YaraType.DOUBLE) == "double"

    def test_static_regex_type(self) -> None:
        """Test static REGEX type instance."""
        assert isinstance(YaraType.REGEX, RegexType)
        assert str(YaraType.REGEX) == "regex"

    def test_static_unknown_type(self) -> None:
        """Test static UNKNOWN type instance."""
        assert isinstance(YaraType.UNKNOWN, UnknownType)
        assert str(YaraType.UNKNOWN) == "unknown"


class TestTypeInference:
    """Tests for TypeInference visitor."""

    def test_infer_integer_literal(self) -> None:
        """Test inferring type of integer literal."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = IntegerLiteral(value=42)
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_double_literal(self) -> None:
        """Test inferring type of double literal."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = DoubleLiteral(value=3.14)
        result = inference.infer(node)
        assert isinstance(result, DoubleType)

    def test_infer_string_literal(self) -> None:
        """Test inferring type of string literal."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = StringLiteral(value="test")
        result = inference.infer(node)
        assert isinstance(result, StringType)

    def test_infer_boolean_literal(self) -> None:
        """Test inferring type of boolean literal."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BooleanLiteral(value=True)
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_identifier_filesize(self) -> None:
        """Test inferring type of filesize identifier."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = Identifier(name="filesize")
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_identifier_entrypoint(self) -> None:
        """Test inferring type of entrypoint identifier."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = Identifier(name="entrypoint")
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_identifier_defined_variable(self) -> None:
        """Test inferring type of defined variable."""
        env = TypeEnvironment()
        env.define("my_var", StringType())
        inference = TypeInference(env)
        node = Identifier(name="my_var")
        result = inference.infer(node)
        assert isinstance(result, StringType)

    def test_infer_identifier_undefined(self) -> None:
        """Test inferring type of undefined identifier."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = Identifier(name="undefined")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)

    def test_infer_string_identifier_defined(self) -> None:
        """Test inferring type of defined string identifier."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringIdentifier(name="$str1")
        result = inference.infer(node)
        assert isinstance(result, StringIdentifierType)

    def test_infer_string_identifier_undefined(self) -> None:
        """Test inferring type of undefined string identifier."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = StringIdentifier(name="$str1")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) == 1
        assert "Undefined string: $str1" in inference.errors[0]

    def test_infer_string_count(self) -> None:
        """Test inferring type of string count."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringCount(string_id="str1")
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_string_offset(self) -> None:
        """Test inferring type of string offset."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringOffset(string_id="str1", index=None)
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_string_length(self) -> None:
        """Test inferring type of string length."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringLength(string_id="str1", index=None)
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_binary_expression_logical_and(self) -> None:
        """Test inferring type of logical AND expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=BooleanLiteral(value=True),
            operator="and",
            right=BooleanLiteral(value=False),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_binary_expression_comparison(self) -> None:
        """Test inferring type of comparison expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="<",
            right=IntegerLiteral(value=10),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_binary_expression_arithmetic_addition(self) -> None:
        """Test inferring type of arithmetic addition."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="+",
            right=IntegerLiteral(value=10),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_binary_expression_arithmetic_division_returns_double(self) -> None:
        """Test inferring type of division returns double."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=IntegerLiteral(value=10),
            operator="/",
            right=IntegerLiteral(value=2),
        )
        result = inference.infer(node)
        assert isinstance(result, DoubleType)

    def test_infer_binary_expression_bitwise_and(self) -> None:
        """Test inferring type of bitwise AND."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="&",
            right=IntegerLiteral(value=3),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_unary_expression_not(self) -> None:
        """Test inferring type of NOT expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = UnaryExpression(
            operator="not",
            operand=BooleanLiteral(value=True),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_unary_expression_negation(self) -> None:
        """Test inferring type of negation expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = UnaryExpression(
            operator="-",
            operand=IntegerLiteral(value=42),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_unary_expression_bitwise_not(self) -> None:
        """Test inferring type of bitwise NOT."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = UnaryExpression(
            operator="~",
            operand=IntegerLiteral(value=42),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_parentheses_expression(self) -> None:
        """Test inferring type of parentheses expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = ParenthesesExpression(expression=IntegerLiteral(value=42))
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_set_expression(self) -> None:
        """Test inferring type of set expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = SetExpression(
            elements=[
                StringLiteral(value="a"),
                StringLiteral(value="b"),
            ],
        )
        result = inference.infer(node)
        assert isinstance(result, StringSetType)

    def test_infer_range_expression(self) -> None:
        """Test inferring type of range expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = RangeExpression(
            low=IntegerLiteral(value=1),
            high=IntegerLiteral(value=10),
        )
        result = inference.infer(node)
        assert isinstance(result, RangeType)

    def test_infer_function_call_uint32(self) -> None:
        """Test inferring type of uint32 function call."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = FunctionCall(
            function="uint32",
            arguments=[IntegerLiteral(value=0)],
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_array_access(self) -> None:
        """Test inferring type of array access."""
        env = TypeEnvironment()
        env.define("arr", ArrayType(element_type=StringType()))
        inference = TypeInference(env)
        node = ArrayAccess(
            array=Identifier(name="arr"),
            index=IntegerLiteral(value=0),
        )
        result = inference.infer(node)
        assert isinstance(result, StringType)

    def test_infer_member_access_module(self) -> None:
        """Test inferring type of module member access."""
        env = TypeEnvironment()
        env.add_module("pe")
        inference = TypeInference(env)

        # Create module type
        module_type = ModuleType(
            module_name="pe",
            attributes={"machine": IntegerType()},
        )
        env.define("pe", module_type)

        node = MemberAccess(
            object=Identifier(name="pe"),
            member="machine",
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_at_expression(self) -> None:
        """Test inferring type of at expression."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = AtExpression(
            string_id="$str1",
            offset=IntegerLiteral(value=100),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_in_expression(self) -> None:
        """Test inferring type of in expression."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = InExpression(
            subject="$str1",
            range=RangeExpression(
                low=IntegerLiteral(value=0),
                high=IntegerLiteral(value=100),
            ),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_of_expression(self) -> None:
        """Test inferring type of of expression."""
        env = TypeEnvironment()
        env.add_string("$str1")
        env.add_string("$str2")
        inference = TypeInference(env)
        node = OfExpression(
            quantifier=IntegerLiteral(value=1),
            string_set=SetExpression(
                elements=[
                    StringIdentifier(name="$str1"),
                    StringIdentifier(name="$str2"),
                ],
            ),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_for_expression(self) -> None:
        """Test inferring type of for expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = ForExpression(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(
                low=IntegerLiteral(value=1),
                high=IntegerLiteral(value=10),
            ),
            body=BooleanLiteral(value=True),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_for_of_expression(self) -> None:
        """Test inferring type of for-of expression."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = ForOfExpression(
            quantifier=IntegerLiteral(value=1),
            string_set=SetExpression(elements=[StringIdentifier(name="$str1")]),
            condition=BooleanLiteral(value=True),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)


class TestTypeChecker:
    """Tests for TypeChecker visitor."""

    def test_type_checker_initialization(self) -> None:
        """Test TypeChecker initializes properly."""
        checker = TypeChecker()
        assert isinstance(checker.env, TypeEnvironment)
        assert isinstance(checker.inference, TypeInference)
        assert len(checker.errors) == 0

    def test_check_compatibility_integer_types(self) -> None:
        """Test checking compatibility between integer types."""
        checker = TypeChecker()
        type1 = IntegerType()
        type2 = IntegerType()
        assert checker.check_compatibility(type1, type2) is True

    def test_check_compatibility_incompatible_types(self) -> None:
        """Test checking compatibility between incompatible types."""
        checker = TypeChecker()
        type1 = IntegerType()
        type2 = StringType()
        assert checker.check_compatibility(type1, type2) is False

    def test_check_compatibility_non_yara_types_uses_equality(self) -> None:
        """Test fallback compatibility path for plain Python values."""
        checker = TypeChecker()
        assert checker.check_compatibility("text", "text") is True
        assert checker.check_compatibility("text", "other") is False

    def test_check_yara_file_with_imports(self) -> None:
        """Test checking YARA file with imports."""
        checker = TypeChecker()
        ast = YaraFile()
        ast.imports = [Import(module="pe")]
        ast.rules = []

        errors = checker.check(ast)
        assert len(errors) == 0
        assert checker.env.has_module("pe") is True

    def test_check_rule_with_strings(self) -> None:
        """Test checking rule with string definitions."""
        checker = TypeChecker()
        rule = Rule(name="test_rule")
        rule.strings = [
            PlainString(identifier="$str1", value="test"),
            PlainString(identifier="$str2", value="data"),
        ]
        rule.condition = BooleanLiteral(value=True)

        ast = YaraFile()
        ast.rules = [rule]

        errors = checker.check(ast)
        assert len(errors) == 0
        assert checker.env.has_string("$str1") is True
        assert checker.env.has_string("$str2") is True

    def test_check_rule_with_integer_condition(self) -> None:
        """Test checking rule with integer condition (valid in YARA)."""
        checker = TypeChecker()
        rule = Rule(name="test_rule")
        rule.strings = []
        rule.condition = IntegerLiteral(value=1)

        ast = YaraFile()
        ast.rules = [rule]

        errors = checker.check(ast)
        # Integer conditions are valid in YARA
        assert len(errors) == 0

    def test_check_rule_with_invalid_condition_type(self) -> None:
        """Test checking rule with invalid condition type."""
        checker = TypeChecker()
        rule = Rule(name="test_rule")
        rule.strings = []
        rule.condition = StringLiteral(value="invalid")

        ast = YaraFile()
        ast.rules = [rule]

        errors = checker.check(ast)
        # String conditions are not valid
        assert len(errors) == 1
        assert "must be boolean, integer, or string identifier" in errors[0]

    def test_infer_type_delegates_to_inference(self) -> None:
        """Test infer_type delegates to TypeInference."""
        checker = TypeChecker()
        node = IntegerLiteral(value=42)
        result = checker.infer_type(node)
        assert isinstance(result, IntegerType)


class TestTypeValidator:
    """Tests for TypeValidator high-level API."""

    def test_validate_valid_yara_file(self) -> None:
        """Test validating a valid YARA file."""
        ast = YaraFile()
        rule = Rule(name="test_rule")
        rule.strings = [PlainString(identifier="$a", value="test")]
        rule.condition = BooleanLiteral(value=True)
        ast.rules = [rule]

        is_valid, errors = TypeValidator.validate(ast)
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_invalid_yara_file(self) -> None:
        """Test validating an invalid YARA file."""
        ast = YaraFile()
        rule = Rule(name="test_rule")
        rule.strings = []
        rule.condition = StringLiteral(value="invalid")
        ast.rules = [rule]

        is_valid, errors = TypeValidator.validate(ast)
        assert is_valid is False
        assert len(errors) > 0

    def test_validate_expression_with_environment(self) -> None:
        """Test validating expression with custom environment."""
        env = TypeEnvironment()
        env.define("x", IntegerType())
        expr = Identifier(name="x")

        expr_type, errors = TypeValidator.validate_expression(expr, env)
        assert isinstance(expr_type, IntegerType)
        assert len(errors) == 0

    def test_validate_expression_without_environment(self) -> None:
        """Test validating expression without custom environment."""
        expr = IntegerLiteral(value=42)

        expr_type, errors = TypeValidator.validate_expression(expr)
        assert isinstance(expr_type, IntegerType)
        assert len(errors) == 0

    def test_validate_expression_with_errors(self) -> None:
        """Test validating expression that generates errors."""
        env = TypeEnvironment()
        expr = StringIdentifier(name="$undefined")

        expr_type, errors = TypeValidator.validate_expression(expr, env)
        assert isinstance(expr_type, UnknownType)
        assert len(errors) > 0


class TestTypeInferenceEdgeCases:
    """Tests for TypeInference edge cases and error paths."""

    def test_infer_identifier_vt_new_file(self) -> None:
        """Test inferring type of VT LiveHunt new_file identifier."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = Identifier(name="new_file")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)

    def test_infer_identifier_vt_positives(self) -> None:
        """Test inferring type of VT LiveHunt positives identifier."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = Identifier(name="positives")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)

    def test_infer_identifier_them(self) -> None:
        """Test inferring type of 'them' identifier."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = Identifier(name="them")
        result = inference.infer(node)
        assert isinstance(result, StringSetType)

    def test_infer_identifier_quantifiers(self) -> None:
        """Test inferring type of quantifier keywords."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        for keyword in ["any", "all", "none"]:
            node = Identifier(name=keyword)
            result = inference.infer(node)
            assert isinstance(result, StringType)

    def test_infer_identifier_rule_reference(self) -> None:
        """Test inferring type of rule reference."""
        env = TypeEnvironment()
        env.add_rule("my_rule")
        inference = TypeInference(env)
        node = Identifier(name="my_rule")
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_string_count_without_dollar_prefix(self) -> None:
        """Test inferring type of string count without $ prefix."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringCount(string_id="str1")
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_string_offset_with_index(self) -> None:
        """Test inferring type of string offset with index."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringOffset(string_id="str1", index=IntegerLiteral(value=0))
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_string_offset_with_invalid_index_type(self) -> None:
        """Test inferring string offset with invalid index type."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringOffset(string_id="str1", index=StringLiteral(value="invalid"))
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0
        assert "String offset index must be integer" in inference.errors[0]

    def test_infer_string_length_with_index(self) -> None:
        """Test inferring type of string length with index."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)
        node = StringLength(string_id="str1", index=IntegerLiteral(value=0))
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_binary_expression_logical_or(self) -> None:
        """Test inferring type of logical OR expression."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=BooleanLiteral(value=True),
            operator="or",
            right=BooleanLiteral(value=False),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_binary_expression_invalid_logical_operand(self) -> None:
        """Test inferring binary expression with invalid logical operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="and",
            right=BooleanLiteral(value=True),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_contains_on_array(self) -> None:
        """Test inferring contains operator on array."""
        env = TypeEnvironment()
        env.define("arr", ArrayType(element_type=IntegerType()))
        inference = TypeInference(env)
        node = BinaryExpression(
            left=Identifier(name="arr"),
            operator="contains",
            right=IntegerLiteral(value=5),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_binary_expression_matches_with_regex(self) -> None:
        """Test inferring matches operator with regex."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        # Import RegexLiteral from the correct module
        from yaraast.ast.expressions import RegexLiteral

        node = BinaryExpression(
            left=StringLiteral(value="test"),
            operator="matches",
            right=RegexLiteral(pattern="[a-z]+"),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_binary_expression_arithmetic_with_double(self) -> None:
        """Test inferring arithmetic with double operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = BinaryExpression(
            left=DoubleLiteral(value=3.14),
            operator="+",
            right=IntegerLiteral(value=2),
        )
        result = inference.infer(node)
        assert isinstance(result, DoubleType)

    def test_infer_binary_expression_bitwise_shift(self) -> None:
        """Test inferring bitwise shift operations."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        for op in ["<<", ">>"]:
            node = BinaryExpression(
                left=IntegerLiteral(value=8),
                operator=op,
                right=IntegerLiteral(value=2),
            )
            result = inference.infer(node)
            assert isinstance(result, IntegerType)

    def test_infer_binary_expression_comparison_operators(self) -> None:
        """Test inferring all comparison operators."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        for op in ["==", "!=", "<=", ">=", ">", "<"]:
            node = BinaryExpression(
                left=IntegerLiteral(value=5),
                operator=op,
                right=IntegerLiteral(value=10),
            )
            result = inference.infer(node)
            assert isinstance(result, BooleanType)

    def test_infer_binary_expression_string_operators(self) -> None:
        """Test inferring string comparison operators."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        for op in [
            "contains",
            "startswith",
            "endswith",
            "icontains",
            "istartswith",
            "iendswith",
            "iequals",
        ]:
            node = BinaryExpression(
                left=StringLiteral(value="test"),
                operator=op,
                right=StringLiteral(value="te"),
            )
            result = inference.infer(node)
            assert isinstance(result, BooleanType)

    def test_infer_set_expression_with_incompatible_types(self) -> None:
        """Test inferring set expression with incompatible element types."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = SetExpression(
            elements=[
                StringLiteral(value="a"),
                IntegerLiteral(value=1),
            ],
        )
        result = inference.infer(node)
        assert isinstance(result, StringSetType)
        assert len(inference.errors) > 0

    def test_infer_range_expression_with_non_integer(self) -> None:
        """Test inferring range expression with non-integer bounds."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = RangeExpression(
            low=StringLiteral(value="a"),
            high=IntegerLiteral(value=10),
        )
        result = inference.infer(node)
        assert isinstance(result, RangeType)
        assert len(inference.errors) > 0

    def test_infer_function_call_all_uintx_variants(self) -> None:
        """Test inferring all uint/int function variants."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        functions = [
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
        ]

        for func in functions:
            node = FunctionCall(function=func, arguments=[IntegerLiteral(value=0)])
            result = inference.infer(node)
            assert isinstance(result, IntegerType)

    def test_infer_function_call_invalid_arity(self) -> None:
        """Test inferring function call with invalid argument count."""
        env = TypeEnvironment()
        inference = TypeInference(env)
        node = FunctionCall(function="uint32", arguments=[])
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0

    def test_infer_array_access_with_invalid_index(self) -> None:
        """Test inferring array access with invalid index type."""
        env = TypeEnvironment()
        env.define("arr", ArrayType(element_type=StringType()))
        inference = TypeInference(env)
        node = ArrayAccess(
            array=Identifier(name="arr"),
            index=StringLiteral(value="invalid"),
        )
        result = inference.infer(node)
        assert isinstance(result, StringType)
        assert len(inference.errors) > 0

    def test_infer_array_access_on_non_array(self) -> None:
        """Test inferring array access on non-array type."""
        env = TypeEnvironment()
        env.define("not_array", IntegerType())
        inference = TypeInference(env)
        node = ArrayAccess(
            array=Identifier(name="not_array"),
            index=IntegerLiteral(value=0),
        )
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0

    def test_infer_member_access_on_struct(self) -> None:
        """Test inferring member access on struct type."""
        env = TypeEnvironment()
        struct = StructType(fields={"name": StringType(), "age": IntegerType()})
        env.define("person", struct)
        inference = TypeInference(env)

        node = MemberAccess(object=Identifier(name="person"), member="name")
        result = inference.infer(node)
        assert isinstance(result, StringType)

    def test_infer_member_access_on_struct_invalid_field(self) -> None:
        """Test inferring member access on struct with invalid field."""
        env = TypeEnvironment()
        struct = StructType(fields={"name": StringType()})
        env.define("person", struct)
        inference = TypeInference(env)

        node = MemberAccess(object=Identifier(name="person"), member="invalid")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0

    def test_infer_member_access_on_non_module_or_struct(self) -> None:
        """Test inferring member access on invalid type."""
        env = TypeEnvironment()
        env.define("x", IntegerType())
        inference = TypeInference(env)

        node = MemberAccess(object=Identifier(name="x"), member="field")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0

    def test_infer_for_expression_with_array_iterable(self) -> None:
        """Test inferring for expression with array iterable."""
        env = TypeEnvironment()
        env.define("items", ArrayType(element_type=StringType()))
        inference = TypeInference(env)

        node = ForExpression(
            quantifier="any",
            variable="item",
            iterable=Identifier(name="items"),
            body=BooleanLiteral(value=True),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)

    def test_infer_for_expression_with_invalid_iterable(self) -> None:
        """Test inferring for expression with invalid iterable."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = ForExpression(
            quantifier="any",
            variable="i",
            iterable=IntegerLiteral(value=5),
            body=BooleanLiteral(value=True),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_for_expression_with_non_boolean_body(self) -> None:
        """Test inferring for expression with non-boolean body."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = ForExpression(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(
                low=IntegerLiteral(value=1),
                high=IntegerLiteral(value=10),
            ),
            body=IntegerLiteral(value=1),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_module_function_call(self) -> None:
        """Test inferring module function call."""
        env = TypeEnvironment()
        env.add_module("pe")
        inference = TypeInference(env)

        node = FunctionCall(function="pe.imphash", arguments=[])
        result = inference.infer(node)
        assert isinstance(result, StringType)

    def test_infer_module_function_call_with_arguments(self) -> None:
        """Test inferring module function call with arguments."""
        env = TypeEnvironment()
        env.add_module("pe")
        inference = TypeInference(env)

        node = FunctionCall(
            function="pe.section_index",
            arguments=[StringLiteral(value=".text")],
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_module_function_call_wrong_arity(self) -> None:
        """Test inferring module function call with wrong number of arguments."""
        env = TypeEnvironment()
        env.add_module("pe")
        inference = TypeInference(env)

        node = FunctionCall(function="pe.section_index", arguments=[])
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0
        assert "expects" in inference.errors[0]

    def test_infer_module_function_call_unknown_function(self) -> None:
        """Test inferring unknown module function call."""
        env = TypeEnvironment()
        env.add_module("pe")
        inference = TypeInference(env)

        node = FunctionCall(function="pe.unknown_func", arguments=[])
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0

    def test_infer_module_function_call_module_not_imported(self) -> None:
        """Test inferring module function call when module not imported."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = FunctionCall(function="pe.imphash", arguments=[])
        result = inference.infer(node)
        # Should return UnknownType since module is not imported
        assert isinstance(result, UnknownType)

    def test_infer_function_call_invalid_arity_all_variants(self) -> None:
        """Test all function variants with invalid argument counts."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        functions = [
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
        ]

        for func in functions:
            # Create new inference for each test to reset errors
            inference = TypeInference(env)
            node = FunctionCall(function=func, arguments=[])
            result = inference.infer(node)
            assert isinstance(result, IntegerType)
            assert len(inference.errors) == 1
            assert "expects 1 argument" in inference.errors[0]

    def test_infer_dictionary_access(self) -> None:
        """Test inferring dictionary access."""
        env = TypeEnvironment()

        # Create a mock dictionary access node
        class DictionaryAccess:
            def __init__(self, obj, key):
                self.object = obj
                self.key = key

            def accept(self, visitor):
                return visitor.visit_dictionary_access(self)

        dict_type = DictionaryType(key_type=StringType(), value_type=IntegerType())
        env.define("mydict", dict_type)
        inference = TypeInference(env)

        node = DictionaryAccess(
            obj=Identifier(name="mydict"),
            key=StringLiteral(value="key"),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)

    def test_infer_dictionary_access_with_wrong_key_type(self) -> None:
        """Test inferring dictionary access with wrong key type."""
        env = TypeEnvironment()

        class DictionaryAccess:
            def __init__(self, obj, key):
                self.object = obj
                self.key = key

            def accept(self, visitor):
                return visitor.visit_dictionary_access(self)

        dict_type = DictionaryType(key_type=StringType(), value_type=IntegerType())
        env.define("mydict", dict_type)
        inference = TypeInference(env)

        node = DictionaryAccess(
            obj=Identifier(name="mydict"),
            key=IntegerLiteral(value=0),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0

    def test_infer_dictionary_access_on_non_dict(self) -> None:
        """Test inferring dictionary access on non-dictionary type."""
        env = TypeEnvironment()

        class DictionaryAccess:
            def __init__(self, obj, key):
                self.object = obj
                self.key = key

            def accept(self, visitor):
                return visitor.visit_dictionary_access(self)

        env.define("not_dict", IntegerType())
        inference = TypeInference(env)

        node = DictionaryAccess(
            obj=Identifier(name="not_dict"),
            key=StringLiteral(value="key"),
        )
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0

    def test_infer_module_reference(self) -> None:
        """Test inferring module reference."""
        env = TypeEnvironment()
        env.add_module("pe")
        inference = TypeInference(env)

        class ModuleReference:
            def __init__(self, module):
                self.module = module

            def accept(self, visitor):
                return visitor.visit_module_reference(self)

        node = ModuleReference(module="pe")
        result = inference.infer(node)
        assert isinstance(result, ModuleType)

    def test_infer_module_reference_not_imported(self) -> None:
        """Test inferring module reference when module not imported."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        class ModuleReference:
            def __init__(self, module):
                self.module = module

            def accept(self, visitor):
                return visitor.visit_module_reference(self)

        node = ModuleReference(module="pe")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0

    def test_infer_for_of_expression_with_invalid_string_set(self) -> None:
        """Test inferring for-of expression with invalid string set type."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = ForOfExpression(
            quantifier=IntegerLiteral(value=1),
            string_set=IntegerLiteral(value=5),  # Invalid: should be StringSetType
            condition=BooleanLiteral(value=True),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_for_of_expression_with_non_boolean_condition(self) -> None:
        """Test inferring for-of expression with non-boolean condition."""
        env = TypeEnvironment()
        env.add_string("$str1")
        inference = TypeInference(env)

        node = ForOfExpression(
            quantifier=IntegerLiteral(value=1),
            string_set=SetExpression(elements=[StringIdentifier(name="$str1")]),
            condition=IntegerLiteral(value=1),  # Invalid: should be boolean
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_string_wildcard(self) -> None:
        """Test inferring string wildcard type."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        class StringWildcard:
            def accept(self, visitor):
                return visitor.visit_string_wildcard(self)

        node = StringWildcard()
        result = inference.infer(node)
        assert isinstance(result, StringSetType)

    def test_type_checker_check_compatibility_with_instances(self) -> None:
        """Test check_compatibility with YaraType instances."""
        checker = TypeChecker()
        result = checker.check_compatibility(IntegerType(), IntegerType())
        assert result is True

    def test_type_checker_visit_methods_coverage(self) -> None:
        """Test various TypeChecker visit methods for coverage."""
        checker = TypeChecker()

        # These methods are intentionally empty but should be callable
        from yaraast.ast.strings import HexString

        # Test various visit methods
        checker.visit_include(None)
        checker.visit_tag(None)
        checker.visit_string_definition(None)
        checker.visit_plain_string(None)
        checker.visit_hex_string(HexString(identifier="$hex", tokens=[]))
        checker.visit_regex_string(None)
        checker.visit_string_modifier(None)
        checker.visit_hex_token(None)
        checker.visit_hex_byte(None)
        checker.visit_hex_wildcard(None)
        checker.visit_hex_jump(None)
        checker.visit_hex_alternative(None)
        checker.visit_hex_nibble(None)
        checker.visit_expression(None)
        checker.visit_identifier(None)
        checker.visit_string_identifier(None)
        checker.visit_string_wildcard(None)
        checker.visit_string_count(None)
        checker.visit_string_offset(None)
        checker.visit_string_length(None)
        checker.visit_integer_literal(None)
        checker.visit_double_literal(None)
        checker.visit_string_literal(None)
        checker.visit_boolean_literal(None)
        checker.visit_binary_expression(None)
        checker.visit_unary_expression(None)
        checker.visit_parentheses_expression(None)
        checker.visit_set_expression(None)
        checker.visit_range_expression(None)
        checker.visit_function_call(None)
        checker.visit_array_access(None)
        checker.visit_member_access(None)
        checker.visit_condition(None)
        checker.visit_for_expression(None)
        checker.visit_for_of_expression(None)
        checker.visit_at_expression(None)
        checker.visit_in_expression(None)
        checker.visit_of_expression(None)
        checker.visit_meta(None)
        checker.visit_module_reference(None)
        checker.visit_dictionary_access(None)
        checker.visit_comment(None)
        checker.visit_comment_group(None)
        checker.visit_defined_expression(None)
        checker.visit_regex_literal(None)
        checker.visit_string_operator_expression(None)
        checker.visit_extern_import(None)
        checker.visit_extern_namespace(None)
        checker.visit_extern_rule(None)
        checker.visit_extern_rule_reference(None)
        checker.visit_in_rule_pragma(None)
        checker.visit_pragma(None)
        checker.visit_pragma_block(None)

        # All visit methods should complete without error
        assert True

    def test_infer_binary_expression_contains_incompatible_array_element(self) -> None:
        """Test contains on array with incompatible element type."""
        env = TypeEnvironment()
        env.define("arr", ArrayType(element_type=IntegerType()))
        inference = TypeInference(env)

        node = BinaryExpression(
            left=Identifier(name="arr"),
            operator="contains",
            right=StringLiteral(value="test"),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0
        assert "not compatible" in inference.errors[0]

    def test_infer_binary_expression_invalid_string_operator_left(self) -> None:
        """Test string operator with non-string-like left operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="startswith",
            right=StringLiteral(value="test"),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_matches_invalid_right(self) -> None:
        """Test matches operator with invalid right operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=StringLiteral(value="test"),
            operator="matches",
            right=IntegerLiteral(value=5),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_string_operator_invalid_right(self) -> None:
        """Test string operator with invalid right operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=StringLiteral(value="test"),
            operator="contains",
            right=IntegerLiteral(value=5),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_arithmetic_invalid_left(self) -> None:
        """Test arithmetic operator with non-numeric left operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=StringLiteral(value="test"),
            operator="+",
            right=IntegerLiteral(value=5),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_arithmetic_invalid_right(self) -> None:
        """Test arithmetic operator with non-numeric right operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="+",
            right=StringLiteral(value="test"),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_bitwise_invalid_left(self) -> None:
        """Test bitwise operator with non-integer left operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=StringLiteral(value="test"),
            operator="&",
            right=IntegerLiteral(value=5),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_bitwise_invalid_right(self) -> None:
        """Test bitwise operator with non-integer right operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="&",
            right=StringLiteral(value="test"),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0

    def test_infer_binary_expression_unknown_operator(self) -> None:
        """Test binary expression with unknown operator."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = BinaryExpression(
            left=IntegerLiteral(value=5),
            operator="???",
            right=IntegerLiteral(value=10),
        )
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0
        assert "Unknown binary operator" in inference.errors[0]

    def test_infer_unary_expression_not_invalid_operand(self) -> None:
        """Test NOT operator with non-boolean operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = UnaryExpression(
            operator="not",
            operand=IntegerLiteral(value=5),
        )
        result = inference.infer(node)
        assert isinstance(result, BooleanType)
        assert len(inference.errors) > 0

    def test_infer_unary_expression_minus_invalid_operand(self) -> None:
        """Test unary minus with non-numeric operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = UnaryExpression(
            operator="-",
            operand=StringLiteral(value="test"),
        )
        result = inference.infer(node)
        assert isinstance(result, StringType)
        assert len(inference.errors) > 0

    def test_infer_unary_expression_bitwise_not_invalid_operand(self) -> None:
        """Test bitwise NOT with non-integer operand."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = UnaryExpression(
            operator="~",
            operand=StringLiteral(value="test"),
        )
        result = inference.infer(node)
        assert isinstance(result, IntegerType)
        assert len(inference.errors) > 0

    def test_infer_unary_expression_unknown_operator(self) -> None:
        """Test unary expression with unknown operator."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        node = UnaryExpression(
            operator="???",
            operand=IntegerLiteral(value=5),
        )
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0
        assert "Unknown unary operator" in inference.errors[0]

    def test_infer_binary_expression_all_arithmetic_operators(self) -> None:
        """Test all arithmetic operators."""
        env = TypeEnvironment()
        inference = TypeInference(env)

        for op in ["-", "*", "%"]:
            inference = TypeInference(env)
            node = BinaryExpression(
                left=IntegerLiteral(value=10),
                operator=op,
                right=IntegerLiteral(value=2),
            )
            result = inference.infer(node)
            assert isinstance(result, IntegerType)

    def test_infer_binary_expression_all_bitwise_operators(self) -> None:
        """Test all bitwise operators."""
        env = TypeEnvironment()

        for op in ["|", "^"]:
            inference = TypeInference(env)
            node = BinaryExpression(
                left=IntegerLiteral(value=8),
                operator=op,
                right=IntegerLiteral(value=4),
            )
            result = inference.infer(node)
            assert isinstance(result, IntegerType)

    def test_infer_member_access_on_module_invalid_attribute(self) -> None:
        """Test member access on module with invalid attribute."""
        env = TypeEnvironment()
        module_type = ModuleType(
            module_name="pe",
            attributes={"machine": IntegerType()},
        )
        env.define("pe", module_type)
        inference = TypeInference(env)

        node = MemberAccess(object=Identifier(name="pe"), member="invalid_attr")
        result = inference.infer(node)
        assert isinstance(result, UnknownType)
        assert len(inference.errors) > 0

    def test_type_system_builtin_modules_fallback(self) -> None:
        """Test TypeSystem fallback to builtin modules."""
        # This test exercises the _init_builtin_modules fallback
        type_sys = TypeSystem()

        # Verify PE module is loaded
        pe_module = type_sys.get_module("pe")
        assert pe_module is not None

        # Verify math module is loaded
        math_module = type_sys.get_module("math")
        assert math_module is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
