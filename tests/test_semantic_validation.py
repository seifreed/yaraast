"""Tests for semantic validation."""

import pytest

from yaraast.ast.base import Location
from yaraast.ast.expressions import FunctionCall, Identifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.parser import YaraParser
from yaraast.types.semantic_validator import (
    FunctionCallValidator,
    SemanticValidator,
    StringIdentifierValidator,
    ValidationError,
    ValidationResult,
)
from yaraast.types.type_system import TypeEnvironment


class TestValidationError:
    """Tests for ValidationError class."""

    def test_validation_error_basic(self) -> None:
        """Test basic validation error."""
        error = ValidationError("Test error message")
        assert error.message == "Test error message"
        assert error.error_type == "semantic"
        assert error.severity == "error"
        assert error.location is None
        assert error.suggestion is None

    def test_validation_error_with_location(self) -> None:
        """Test validation error with location."""
        location = Location(line=10, column=5, file="test.yar")
        error = ValidationError("Test error", location=location)

        str_repr = str(error)
        assert "test.yar:10:5" in str_repr
        assert "error: Test error" in str_repr

    def test_validation_error_to_dict(self) -> None:
        """Test converting validation error to dictionary."""
        location = Location(line=10, column=5, file="test.yar")
        error = ValidationError(
            "Test error",
            location=location,
            suggestion="Try this fix",
        )

        result = error.to_dict()
        assert result["message"] == "Test error"
        assert result["error_type"] == "semantic"
        assert result["severity"] == "error"
        assert result["suggestion"] == "Try this fix"
        assert result["location"]["file"] == "test.yar"
        assert result["location"]["line"] == 10
        assert result["location"]["column"] == 5


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_validation_result_empty(self) -> None:
        """Test empty validation result."""
        result = ValidationResult()
        assert result.is_valid is True
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
        assert result.total_issues == 0

    def test_add_error(self) -> None:
        """Test adding an error."""
        result = ValidationResult()
        result.add_error("Test error")

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0].message == "Test error"
        assert result.total_issues == 1

    def test_add_warning(self) -> None:
        """Test adding a warning."""
        result = ValidationResult()
        result.add_warning("Test warning")

        assert result.is_valid is True  # Warnings don't invalidate
        assert len(result.warnings) == 1
        assert result.warnings[0].message == "Test warning"
        assert result.total_issues == 1

    def test_combine_results(self) -> None:
        """Test combining validation results."""
        result1 = ValidationResult()
        result1.add_error("Error 1")
        result1.add_warning("Warning 1")

        result2 = ValidationResult()
        result2.add_error("Error 2")

        result1.combine(result2)

        assert result1.is_valid is False
        assert len(result1.errors) == 2
        assert len(result1.warnings) == 1
        assert result1.total_issues == 3


class TestStringIdentifierValidator:
    """Tests for string identifier uniqueness validation."""

    def create_rule_with_strings(self, string_identifiers):
        """Helper to create rule with string identifiers."""
        rule = Rule(name="test_rule")
        for identifier in string_identifiers:
            string_def = PlainString(identifier=identifier, value="test")
            rule.strings.append(string_def)
        return rule

    def test_unique_string_identifiers(self) -> None:
        """Test rule with unique string identifiers."""
        rule = self.create_rule_with_strings(["$a", "$b", "$c"])
        result = ValidationResult()
        validator = StringIdentifierValidator(result)
        validator.visit(rule)

        assert result.is_valid is True
        assert len(result.errors) == 0

    def test_duplicate_string_identifiers(self) -> None:
        """Test rule with duplicate string identifiers."""
        rule = self.create_rule_with_strings(["$a", "$b", "$a"])
        result = ValidationResult()
        validator = StringIdentifierValidator(result)
        validator.visit(rule)

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "Duplicate string identifier '$a'" in result.errors[0].message
        assert "test_rule" in result.errors[0].message

    def test_string_identifiers_without_dollar_prefix(self) -> None:
        """Test handling of string identifiers without $ prefix."""
        rule = self.create_rule_with_strings(["a", "b", "a"])
        result = ValidationResult()
        validator = StringIdentifierValidator(result)
        validator.visit(rule)

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "Duplicate string identifier '$a'" in result.errors[0].message


class TestFunctionCallValidator:
    """Tests for function call validation."""

    def test_builtin_function_valid_arity(self) -> None:
        """Test builtin function with correct arity."""
        func_call = FunctionCall(
            function="uint32",
            arguments=[Identifier(name="offset")],
        )

        env = TypeEnvironment()
        result = ValidationResult()
        validator = FunctionCallValidator(result, env)
        validator.visit(func_call)

        assert result.is_valid is True
        assert len(result.errors) == 0

    def test_builtin_function_invalid_arity(self) -> None:
        """Test builtin function with incorrect arity."""
        func_call = FunctionCall(
            function="uint32",
            arguments=[],
        )  # Should have 1 argument

        env = TypeEnvironment()
        result = ValidationResult()
        validator = FunctionCallValidator(result, env)
        validator.visit(func_call)

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "expects at least 1 argument" in result.errors[0].message

    def test_module_function_not_imported(self) -> None:
        """Test module function call without import."""
        func_call = FunctionCall(function="pe.imphash", arguments=[])

        env = TypeEnvironment()  # No modules imported
        result = ValidationResult()
        validator = FunctionCallValidator(result, env)
        validator.visit(func_call)

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "Module 'pe' not imported" in result.errors[0].message

    def test_module_function_imported(self) -> None:
        """Test module function call with import."""
        func_call = FunctionCall(function="pe.imphash", arguments=[])

        env = TypeEnvironment()
        env.add_module("pe")  # Import pe module
        result = ValidationResult()
        validator = FunctionCallValidator(result, env)
        validator.visit(func_call)

        # Should be valid (pe.imphash exists and takes 0 arguments)
        assert result.is_valid is True
        assert len(result.errors) == 0

    def test_unknown_module_function(self) -> None:
        """Test unknown function in known module."""
        func_call = FunctionCall(function="pe.unknown_func", arguments=[])

        env = TypeEnvironment()
        env.add_module("pe")
        result = ValidationResult()
        validator = FunctionCallValidator(result, env)
        validator.visit(func_call)

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "Function 'unknown_func' not found in module 'pe'" in result.errors[0].message

    def test_unknown_function_warning(self) -> None:
        """Test unknown function generates warning."""
        func_call = FunctionCall(function="unknown_func", arguments=[])

        env = TypeEnvironment()
        result = ValidationResult()
        validator = FunctionCallValidator(result, env)
        validator.visit(func_call)

        assert result.is_valid is True  # Warnings don't invalidate
        assert len(result.warnings) == 1
        assert "Unknown function 'unknown_func'" in result.warnings[0].message


class TestSemanticValidator:
    """Tests for comprehensive semantic validation."""

    def test_valid_yara_file(self) -> None:
        """Test validation of valid YARA file."""
        yara_code = """
        import "pe"

        rule test_rule {
            strings:
                $a = "hello"
                $b = "world"
            condition:
                $a and $b and pe.imphash() == "test"
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_code)

        validator = SemanticValidator()
        result = validator.validate(ast)

        # Should be valid (assuming parser works correctly)
        assert isinstance(result, ValidationResult)

    def test_duplicate_strings_in_rule(self) -> None:
        """Test detection of duplicate string identifiers."""
        yara_code = """
        rule test_rule {
            strings:
                $a = "hello"
                $b = "world"
                $a = "duplicate"
            condition:
                $a and $b
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_code)

        validator = SemanticValidator()
        result = validator.validate(ast)

        # Should detect the duplicate string identifier
        assert result.is_valid is False
        assert any("Duplicate string identifier" in error.message for error in result.errors)

    def test_module_function_validation_integration(self) -> None:
        """Test integration of module function validation."""
        yara_code = """
        import "pe"

        rule test_rule {
            strings:
                $a = "test"
            condition:
                $a and pe.unknown_function()
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_code)

        validator = SemanticValidator()
        result = validator.validate(ast)

        # Should detect unknown function
        assert result.is_valid is False
        assert any("not found in module" in error.message for error in result.errors)


if __name__ == "__main__":
    pytest.main([__file__])
