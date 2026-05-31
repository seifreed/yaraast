"""Tests for semantic validation."""

from __future__ import annotations

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
    Identifier,
    StringIdentifier,
    StringLiteral,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.parser.parser import Parser
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

    def create_rule_with_strings(self, string_identifiers: list[str]) -> Rule:
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

    def test_console_log_accepts_libyara_scalar_signatures(self) -> None:
        ast = Parser().parse("""
            import "console"
            rule console_log {
                condition:
                    console.log("x") and
                    console.log(1) and
                    console.log(1.5) and
                    console.log("x", 1) and
                    console.log("x", 1.5)
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True
        assert result.errors == []

    def test_console_log_rejects_non_libyara_signatures(self) -> None:
        no_args_ast = Parser().parse('import "console" rule r { condition: console.log() }')
        bool_ast = Parser().parse('import "console" rule r { condition: console.log(true) }')
        first_arg_ast = Parser().parse('import "console" rule r { condition: console.log(1, "x") }')
        too_many_ast = Parser().parse(
            'import "console" rule r { condition: console.log("x", 1, 1.5) }'
        )

        no_args_result = SemanticValidator().validate(no_args_ast)
        bool_result = SemanticValidator().validate(bool_ast)
        first_arg_result = SemanticValidator().validate(first_arg_ast)
        too_many_result = SemanticValidator().validate(too_many_ast)

        assert no_args_result.is_valid is False
        assert "expects at least 1 argument" in no_args_result.errors[0].message
        assert bool_result.is_valid is False
        assert "must be scalar" in bool_result.errors[0].message
        assert first_arg_result.is_valid is False
        assert any(
            "requires a string first argument" in error.message for error in first_arg_result.errors
        )
        assert too_many_result.is_valid is False
        assert any(
            "expects at most 2 argument" in error.message for error in too_many_result.errors
        )

    def test_console_hex_accepts_integer_argument(self) -> None:
        ast = Parser().parse("""
            import "console"
            rule console_hex {
                condition:
                    console.hex(10)
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True
        assert result.errors == []

    def test_console_hex_rejects_non_integer_arguments(self) -> None:
        bool_ast = Parser().parse('import "console" rule r { condition: console.hex(true) }')
        string_ast = Parser().parse('import "console" rule r { condition: console.hex("x") }')

        bool_result = SemanticValidator().validate(bool_ast)
        string_result = SemanticValidator().validate(string_ast)

        assert bool_result.is_valid is False
        assert any("must be integer, got boolean" in e.message for e in bool_result.errors)
        assert string_result.is_valid is False
        assert any("must be integer, got string" in e.message for e in string_result.errors)

    def test_string_to_int_accepts_optional_integer_base(self) -> None:
        ast = Parser().parse("""
            import "string"
            rule string_to_int {
                condition:
                    string.to_int("10", 16) == 16
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True
        assert result.errors == []

    def test_string_to_int_rejects_boolean_base(self) -> None:
        ast = Parser().parse("""
            import "string"
            rule invalid_string_to_int {
                condition:
                    string.to_int("10", true) == 10
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert "must be integer" in result.errors[0].message

    def test_integer_function_parameters_reject_float_arguments(self) -> None:
        ast = Parser().parse("""
            import "math"
            import "string"
            rule invalid_integer_arguments {
                condition:
                    math.abs(1.5) == 1 or
                    string.to_int("10", 1.5) == 10 or
                    uint8(1.5) == 0
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert sum("must be integer, got double" in error.message for error in result.errors) == 3

    def test_double_function_parameters_reject_integer_arguments(self) -> None:
        ast = Parser().parse("""
            import "math"
            rule invalid_double_argument {
                condition:
                    math.deviation(0, 1, 97) >= 0.0
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert "Function 'deviation' does not accept argument types" in result.errors[0].message

    def test_validate_accepts_libyara_math_string_and_region_signatures(self) -> None:
        ast = Parser().parse("""
            import "math"

            rule valid_math_signatures {
                condition:
                    math.entropy("abc") >= 0.0 or
                    math.mean("abc") >= 0.0 or
                    math.deviation("abc", 97.0) >= 0.0 or
                    math.serial_correlation("abc") >= -100000.0 or
                    math.monte_carlo_pi("abcdef") >= 0.0 or
                    math.count(97, 0, filesize) >= 0 or
                    math.percentage(97, 0, filesize) >= 0.0 or
                    math.mode(0, filesize) >= 0
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_invalid_math_function_signatures(self) -> None:
        ast = Parser().parse("""
            import "math"

            rule invalid_math_signatures {
                condition:
                    math.entropy(0) >= 0.0 or
                    math.mean("abc", 1) >= 0.0 or
                    math.deviation("abc", 97) >= 0.0 or
                    math.count(97, "abc") >= 0 or
                    math.percentage(97, "abc") >= 0.0 or
                    math.mode("abc") >= 0
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("Function 'entropy' does not accept argument types" in msg for msg in messages)
        assert any("Function 'mean' does not accept argument types" in msg for msg in messages)
        assert any("Function 'deviation' does not accept argument types" in msg for msg in messages)
        assert any("Function 'count' does not accept argument types" in msg for msg in messages)
        assert any(
            "Function 'percentage' does not accept argument types" in msg for msg in messages
        )
        assert any("Function 'mode' does not accept argument types" in msg for msg in messages)

    def test_modulo_rejects_float_operands(self) -> None:
        ast = Parser().parse("""
            rule invalid_float_modulo {
                condition:
                    7.0 % 2.0 == 1.0
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert any("operand of '%' must be integer" in error.message for error in result.errors)

    def test_logical_operators_accept_numeric_truthiness(self) -> None:
        ast = Parser().parse("""
            rule numeric_truthiness {
                condition:
                    not 0 and 1 and 1.0 and (0.0 or true)
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True
        assert result.errors == []

    def test_cuckoo_nested_module_functions_validate(self) -> None:
        ast = Parser().parse(r"""
            import "cuckoo"
            rule cuckoo_behavior {
                condition:
                    cuckoo.network.http_request(/evil/) and
                    cuckoo.network.tcp(/127\.0\.0\.1/, 443) and
                    cuckoo.registry.key_access(/Run/) and
                    cuckoo.filesystem.file_access(/autoexec/) and
                    cuckoo.sync.mutex(/Mutex/)
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True
        assert result.errors == []

    def test_cuckoo_network_port_functions_reject_boolean_port(self) -> None:
        ast = Parser().parse(r"""
            import "cuckoo"
            rule invalid_cuckoo {
                condition:
                    cuckoo.network.tcp(/127\.0\.0\.1/, true)
            }
            """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert "must be integer" in result.errors[0].message

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

    def test_validate_rejects_defined_on_module_collection_values(self) -> None:
        ast = Parser().parse("""
            import "pe"
            import "dotnet"

            rule invalid_defined_collections {
                condition:
                    defined pe.sections or
                    defined pe.version_info or
                    defined dotnet.resources or
                    defined dotnet.assembly
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any(
            "'defined' cannot be applied to non-scalar expression" in msg for msg in messages
        )

    def test_validate_allows_defined_on_module_collection_subfields(self) -> None:
        ast = Parser().parse("""
            import "pe"
            import "dotnet"

            rule valid_defined_collection_subfields {
                condition:
                    defined pe.sections[0].name or
                    defined pe.version_info["CompanyName"] or
                    defined dotnet.resources[0].name or
                    defined dotnet.assembly.name
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_accepts_defined_on_libyara_scalar_expressions(self) -> None:
        ast = Parser().parse("""
            rule defined_scalar_expressions {
                condition:
                    defined -1 and
                    defined 1.0 and
                    defined "abc" and
                    defined /a/ and
                    defined (1 + 2) and
                    defined (1 < 2)
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_accepts_defined_on_libyara_expression_operands(self) -> None:
        ast = Parser().parse("""
            rule defined_expression_operands {
                condition:
                    defined not ("abc") and
                    defined 1 + 2 and
                    defined 1 == 1 and
                    defined 0 % ~(1)
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_accepts_libyara_dotnet_collection_fields(self) -> None:
        ast = Parser().parse("""
            import "dotnet"

            rule valid_dotnet_collection_fields {
                condition:
                    dotnet.guids[0] == "" or
                    dotnet.user_strings[0] == "" or
                    dotnet.assembly.version.build_number == 0 or
                    dotnet.assembly.version.revision_number == 0 or
                    dotnet.assembly_refs[0].name == "" or
                    dotnet.assembly_refs[0].version.major == 0 or
                    dotnet.assembly_refs[0].version.minor == 0 or
                    dotnet.assembly_refs[0].version.build_number == 0 or
                    dotnet.assembly_refs[0].version.revision_number == 0 or
                    dotnet.assembly_refs[0].public_key_or_token == ""
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_invalid_dotnet_assembly_ref_fields(self) -> None:
        ast = Parser().parse("""
            import "dotnet"

            rule invalid_dotnet_assembly_ref_fields {
                condition:
                    dotnet.assembly_refs[0].culture == ""
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert any("Struct has no field 'culture'" in error.message for error in result.errors)

    def test_validate_accepts_libyara_pe_import_export_signatures(self) -> None:
        ast = Parser().parse("""
            import "pe"

            rule valid_pe_signatures {
                condition:
                    pe.imports("kernel32.dll") or
                    pe.imports("kernel32.dll", "CreateFileA") or
                    pe.imports("kernel32.dll", 1) or
                    pe.imports(/kernel32/i, /CreateFile/i) or
                    pe.imports(1, "CreateFileA") or
                    pe.imports(1, "kernel32.dll", "CreateFileA") or
                    pe.imports(1, "kernel32.dll", 1) or
                    pe.imports(1, /kernel32/i, /CreateFile/i) or
                    pe.exports("ExportedFunc") or
                    pe.exports(/Exported/i) or
                    pe.exports(1) or
                    pe.section_index(".text") == 0 or
                    pe.section_index(1) == 0
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_invalid_pe_import_export_signatures(self) -> None:
        ast = Parser().parse("""
            import "pe"

            rule invalid_pe_signatures {
                condition:
                    pe.imports(/kernel32/i) or
                    pe.imports("kernel32.dll", /CreateFile/i) or
                    pe.imports(1, 2) or
                    pe.imports("kernel32.dll", "CreateFileA", "extra") or
                    pe.exports(true) or
                    pe.section_index(true)
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("Function 'imports' does not accept argument types" in msg for msg in messages)
        assert any("Function 'exports' does not accept argument type" in msg for msg in messages)
        assert any(
            "Function 'section_index' does not accept argument type" in msg for msg in messages
        )

    def test_validate_accepts_libyara_hash_string_and_region_signatures(self) -> None:
        ast = Parser().parse("""
            import "hash"

            rule valid_hash_signatures {
                condition:
                    hash.md5("abc") == "900150983cd24fb0d6963f7d28e17f72" or
                    hash.sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d" or
                    hash.sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" or
                    hash.checksum32("abc") == 294 or
                    hash.crc32("abc") == 891568578 or
                    hash.md5(0, filesize) == "900150983cd24fb0d6963f7d28e17f72"
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_invalid_hash_function_signatures(self) -> None:
        ast = Parser().parse("""
            import "hash"

            rule invalid_hash_signatures {
                condition:
                    hash.md5(0) == "" or
                    hash.sha1("abc", 1) == "" or
                    hash.sha256(true) == ""
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("Function 'md5' does not accept argument types" in msg for msg in messages)
        assert any("Function 'sha1' does not accept argument types" in msg for msg in messages)
        assert any("Function 'sha256' does not accept argument types" in msg for msg in messages)

    def test_validate_accepts_libyara_pe_section_fields(self) -> None:
        ast = Parser().parse("""
            import "pe"

            rule valid_pe_section_fields {
                condition:
                    pe.sections[0].full_name or
                    pe.sections[0].raw_data_offset or
                    pe.sections[0].raw_data_size or
                    pe.sections[0].pointer_to_relocations or
                    pe.sections[0].pointer_to_line_numbers or
                    pe.sections[0].number_of_relocations or
                    pe.sections[0].number_of_line_numbers
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_accepts_libyara_pe_rich_overlay_and_signature_fields(self) -> None:
        ast = Parser().parse("""
            import "pe"

            rule valid_pe_rich_overlay_and_signature_fields {
                condition:
                    pe.overlay.offset >= 0 or
                    pe.overlay.size >= 0 or
                    pe.rich_signature.offset >= 0 or
                    pe.rich_signature.length >= 0 or
                    pe.rich_signature.clear_data == "" or
                    pe.rich_signature.key == 0 or
                    pe.rich_signature.raw_data == "" or
                    pe.rich_signature.version(1) == 0 or
                    pe.rich_signature.version(1, 2) == 0 or
                    pe.rich_signature.toolid(1) == 0 or
                    pe.rich_signature.toolid(1, 2) == 0 or
                    pe.number_of_signatures == 0 or
                    pe.signatures[0].issuer == "" or
                    pe.signatures[0].subject == "" or
                    pe.signatures[0].serial == "" or
                    pe.signatures[0].thumbprint == "" or
                    pe.signatures[0].version == 0 or
                    pe.signatures[0].not_before == 0 or
                    pe.signatures[0].not_after == 0 or
                    pe.signatures[0].digest_alg == "" or
                    pe.signatures[0].file_digest == "" or
                    pe.signatures[0].number_of_certificates == 0 or
                    pe.signatures[0].certificates[0].issuer == "" or
                    pe.signatures[0].certificates[0].subject == "" or
                    pe.signatures[0].certificates[0].serial == "" or
                    pe.signatures[0].certificates[0].thumbprint == "" or
                    pe.signatures[0].certificates[0].version == 0 or
                    pe.signatures[0].certificates[0].not_before == 0 or
                    pe.signatures[0].certificates[0].not_after == 0
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_invalid_pe_extended_fields(self) -> None:
        ast = Parser().parse("""
            import "pe"

            rule invalid_pe_extended_fields {
                condition:
                    pe.overlay.raw_data_offset == 0 or
                    pe.signatures[0].certificates[0].unsupported == ""
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("Struct has no field 'raw_data_offset'" in msg for msg in messages)
        assert any("Struct has no field 'unsupported'" in msg for msg in messages)

    def test_validate_rejects_invalid_pe_section_fields(self) -> None:
        ast = Parser().parse("""
            import "pe"

            rule invalid_pe_section_fields {
                condition:
                    pe.sections[0].raw_size
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert any("Struct has no field 'raw_size'" in error.message for error in result.errors)

    def test_validate_accepts_libyara_elf_module_fields(self) -> None:
        ast = Parser().parse("""
            import "elf"

            rule valid_elf_fields {
                condition:
                    elf.sh_offset or
                    elf.sh_entry_size or
                    elf.ph_offset or
                    elf.ph_entry_size or
                    elf.sections[0].flags or
                    elf.segments[0].flags or
                    elf.segments[0].alignment or
                    elf.symtab[0].name or
                    elf.symtab[0].value or
                    elf.symtab[0].size or
                    elf.symtab[0].type or
                    elf.symtab[0].bind or
                    elf.symtab[0].shndx or
                    elf.dynsym[0].name or
                    elf.dynsym[0].value or
                    elf.dynsym[0].size or
                    elf.dynsym[0].type or
                    elf.dynsym[0].bind or
                    elf.dynsym[0].shndx or
                    elf.dynamic[0].type or
                    elf.dynamic[0].val
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_invalid_elf_module_fields(self) -> None:
        ast = Parser().parse("""
            import "elf"

            rule invalid_elf_fields {
                condition:
                    elf.sh_number or
                    elf.sections[0].link or
                    elf.symtab[0].visibility
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("Module 'elf' has no attribute 'sh_number'" in msg for msg in messages)
        assert any("Struct has no field 'link'" in msg for msg in messages)
        assert any("Struct has no field 'visibility'" in msg for msg in messages)

    def test_validate_rejects_unavailable_magic_module(self) -> None:
        ast = Parser().parse("""
            import "magic"

            rule unavailable_magic_module {
                condition:
                    magic.mime_type == ""
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert any("Unknown module: magic" in error.message for error in result.errors)

    def test_validate_libyara_truthy_scalar_conditions(self) -> None:
        ast = Parser().parse("""
            rule string_literal_condition {
                condition:
                    "abc"
            }

            rule double_literal_condition {
                condition:
                    1.0
            }

            rule regex_literal_condition {
                condition:
                    /a/
            }

            rule string_logical_operand {
                condition:
                    "abc" and true
            }

            rule double_logical_operand {
                condition:
                    not -0.0
            }

            rule regex_logical_operand {
                strings:
                    $a = "abc"
                condition:
                    /a/ and $a
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_raw_string_identifier_binary_operands(self) -> None:
        ast = YaraFile(
            rules=[
                Rule(
                    name="raw_string_identifier_comparison",
                    strings=[PlainString(identifier="$a", value="abc")],
                    condition=BinaryExpression(StringIdentifier("$a"), "==", BooleanLiteral(True)),
                ),
                Rule(
                    name="raw_string_identifier_string_operator",
                    strings=[PlainString(identifier="$a", value="abc")],
                    condition=BinaryExpression(
                        StringIdentifier("$a"),
                        "contains",
                        StringLiteral("a"),
                    ),
                ),
            ]
        )

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("String identifiers cannot be used with '=='" in message for message in messages)
        assert any(
            "Left operand of 'contains' must be string, got string_identifier" in message
            for message in messages
        )

    def test_validate_rejects_boolean_comparison_operands(self) -> None:
        ast = Parser().parse("""
            rule boolean_equality {
                condition:
                    true == true
            }

            rule relational_result_equality {
                condition:
                    (1 < 2) == true
            }

            rule boolean_inequality {
                condition:
                    false != true
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert sum("Boolean operands cannot be used with" in message for message in messages) == 3

    def test_validate_allows_module_boolean_numeric_comparisons(self) -> None:
        ast = Parser().parse("""
            import "console"
            import "pe"
            rule module_boolean_numeric_comparisons {
                condition:
                    pe.is_pe == 0 and
                    pe.is_pe < 1 and
                    console.log("x") == 1 and
                    console.log("x") > 0
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True
        assert result.errors == []

    def test_validate_rejects_invalid_regex_string_operations(self) -> None:
        ast = Parser().parse("""
            rule invalid_regex_string_operations {
                condition:
                    "abc" matches "a" or
                    /a/ == "a" or
                    /a/ == /a/ or
                    /a/ contains "a" or
                    /a/ matches /a/
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("Right operand of 'matches' must be regex" in message for message in messages)
        assert any("Regex operands cannot be used with '=='" in message for message in messages)
        assert any(
            "Left operand of 'contains' must be string-like or array, got regex" in message
            for message in messages
        )
        assert any(
            "Left operand of 'matches' must be string-like or array, got regex" in message
            for message in messages
        )

    def test_validate_rejects_undefined_identifiers_in_comparison_and_defined(self) -> None:
        ast = Parser().parse("""
            rule undefined_identifier_equality {
                condition:
                    missing_equal == missing_equal
            }

            rule undefined_identifier_relational {
                condition:
                    missing_order < 1
            }

            rule undefined_identifier_defined {
                condition:
                    defined missing_defined
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any("Undefined identifier: missing_equal" in message for message in messages)
        assert any("Undefined identifier: missing_order" in message for message in messages)
        assert any("Undefined identifier: missing_defined" in message for message in messages)

    def test_validate_accepts_declared_external_variables(self) -> None:
        ast = Parser().parse("""
            rule external_variables {
                condition:
                    ext_int == 1 and
                    ext_str == "x" and
                    ext_bool and
                    ext_float == 1.5
            }
        """)

        result = SemanticValidator(
            externals={
                "ext_int": 1,
                "ext_str": "x",
                "ext_bool": True,
                "ext_float": 1.5,
            }
        ).validate(ast)

        assert result.is_valid is True

    def test_validate_rejects_external_variables_with_wrong_types(self) -> None:
        ast = Parser().parse("""
            rule external_variable_types {
                condition:
                    ext_int contains "x" or
                    ext_bool == true
            }
        """)

        result = SemanticValidator().validate(ast, externals={"ext_int": 1, "ext_bool": True})

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert any(
            "Left operand of 'contains' must be string-like or array, got integer" in msg
            for msg in messages
        )
        assert any("Boolean operands cannot be used with '=='" in msg for msg in messages)

    def test_validate_rejects_integer_division_and_modulo_by_zero(self) -> None:
        ast = Parser().parse(r"""
            rule string_count_division_by_zero {
                strings:
                    $a = "abc"
                condition:
                    #a \ 0
            }

            rule string_offset_modulo_by_zero {
                strings:
                    $a = "abc"
                condition:
                    @a % 0
            }

            rule folded_shift_division_by_zero {
                strings:
                    $a = "abc"
                condition:
                    #a \ (1 << 64)
            }

            rule folded_bitwise_modulo_by_zero {
                strings:
                    $a = "abc"
                condition:
                    @a % (1 & 2)
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert sum("Right operand of '\\' cannot be zero" in message for message in messages) == 2
        assert sum("Right operand of '%' cannot be zero" in message for message in messages) == 2

    def test_validate_rejects_constant_negative_shift_counts(self) -> None:
        ast = Parser().parse("""
            rule direct_negative_shift_left {
                condition:
                    1 << -1 == 0
            }

            rule parenthesized_negative_shift_right {
                condition:
                    1 >> (0 - 1) == 0
            }

            rule dynamic_shift_count {
                condition:
                    1 << (filesize - 2) == 0
            }
        """)

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        messages = [error.message for error in result.errors]
        assert (
            sum("Right operand of '<<' cannot be negative" in message for message in messages) == 1
        )
        assert (
            sum("Right operand of '>>' cannot be negative" in message for message in messages) == 1
        )

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

        parser = Parser(yara_code)
        ast = parser.parse()

        validator = SemanticValidator()
        result = validator.validate(ast)

        # Should be valid (assuming parser works correctly)
        assert isinstance(result, ValidationResult)

    def test_duplicate_strings_in_rule(self) -> None:
        """Test detection of duplicate string identifiers."""
        ast = YaraFile(
            rules=[
                Rule(
                    name="test_rule",
                    strings=[
                        PlainString("$a", value="hello"),
                        PlainString("$b", value="world"),
                        PlainString("$a", value="duplicate"),
                    ],
                    condition=Identifier("$a"),
                )
            ]
        )

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

        parser = Parser(yara_code)
        ast = parser.parse()

        validator = SemanticValidator()
        result = validator.validate(ast)

        # Should detect unknown function
        assert result.is_valid is False
        assert any("not found in module" in error.message for error in result.errors)


if __name__ == "__main__":
    pytest.main([__file__])
