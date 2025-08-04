"""Example of using libyara integration for cross-validation."""

from yaraast.libyara import YARA_AVAILABLE, EquivalenceTester, LibyaraCompiler, LibyaraScanner
from yaraast.libyara.cross_validator import CrossValidator
from yaraast.parser import Parser


def example_compilation() -> None:
    """Example: Compile AST using libyara."""
    print("=== LibYARA Compilation Example ===\n")

    if not YARA_AVAILABLE:
        print("Error: yara-python is not installed")
        print("Install with: pip install yara-python")
        return

    # Parse YARA rules
    rule_text = """
    import "pe"

    rule malware_detection {
        meta:
            author = "Security Team"
            description = "Detects suspicious patterns"

        strings:
            $mz = { 4D 5A }  // MZ header
            $suspicious = "CreateRemoteThread"
            $registry = /Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/

        condition:
            $mz at 0 and
            ($suspicious or $registry) and
            pe.number_of_sections > 3
    }
    """

    parser = Parser()
    ast = parser.parse(rule_text)

    # Compile with libyara
    compiler = LibyaraCompiler()
    result = compiler.compile_ast(ast)

    if result.success:
        print("✓ Compilation successful!")
        print(f"  Source code length: {len(result.source_code)} bytes")
        print(f"  Warnings: {len(result.warnings)}")

        # Save compiled rules
        if compiler.save_compiled_rules(result.compiled_rules, "compiled.yarc"):
            print("✓ Saved compiled rules to 'compiled.yarc'")
    else:
        print("✗ Compilation failed!")
        for error in result.errors:
            print(f"  Error: {error}")


def example_scanning() -> None:
    """Example: Scan data with libyara."""
    print("\n=== LibYARA Scanning Example ===\n")

    if not YARA_AVAILABLE:
        return

    # Simple rule
    rule_text = """
    rule detect_patterns {
        strings:
            $a = "malicious"
            $b = { 48 65 6c 6c 6f }  // "Hello" in hex
            $c = /[0-9]{3}-[0-9]{3}-[0-9]{4}/  // Phone number pattern

        condition:
            any of them
    }
    """

    # Compile
    compiler = LibyaraCompiler()
    compilation = compiler.compile_source(rule_text)

    if not compilation.success:
        print("Compilation failed!")
        return

    # Test data
    test_samples = [
        b"This is a malicious file",
        b"Hello world! Call me at 123-456-7890",
        b"Nothing suspicious here",
        b"Another malicious sample with phone: 555-123-4567",
    ]

    # Scan each sample
    scanner = LibyaraScanner()

    for i, data in enumerate(test_samples):
        result = scanner.scan_data(compilation.compiled_rules, data)

        print(f"Sample {i + 1}: ", end="")
        if result.matched:
            print(f"MATCHED ({', '.join(result.matched_rules)})")
            for match in result.matches:
                print(f"  - Rule: {match.rule}")
                for string_match in match.strings:
                    print(
                        f"    String: {string_match['identifier']} at offset {string_match['offset']}"
                    )
        else:
            print("No match")


def example_cross_validation() -> None:
    """Example: Cross-validate between yaraast and libyara."""
    print("\n=== Cross-Validation Example ===\n")

    if not YARA_AVAILABLE:
        return

    # Complex rule to validate
    rule_text = """
    rule validate_example {
        strings:
            $str1 = "test"
            $str2 = "example" nocase
            $hex = { 41 42 43 ?? 45 }

        condition:
            #str1 > 1 and
            $str2 and
            $hex and
            @str1[1] > @str1[0] and
            filesize > 50
    }
    """

    parser = Parser()
    ast = parser.parse(rule_text)

    # Test data
    test_data = b"test example TEST ABC?E more test data to increase filesize beyond 50 bytes"

    # Cross-validate
    validator = CrossValidator()
    result = validator.validate(ast, test_data)

    print(f"Validation result: {'PASSED' if result.valid else 'FAILED'}")
    print(f"Rules tested: {result.rules_tested}")
    print(f"Match agreement: {result.match_rate:.1f}%")

    print("\nResults comparison:")
    for rule_name in result.yaraast_results:
        yaraast = result.yaraast_results[rule_name]
        libyara = result.libyara_results[rule_name]
        match = "✓" if yaraast == libyara else "✗"
        print(f"  {match} {rule_name}: yaraast={yaraast}, libyara={libyara}")

    print("\nPerformance:")
    print(f"  YaraAST: {result.yaraast_time * 1000:.1f}ms")
    print(f"  LibYARA compile: {result.libyara_compile_time * 1000:.1f}ms")
    print(f"  LibYARA scan: {result.libyara_scan_time * 1000:.1f}ms")


def example_round_trip() -> None:
    """Example: Test AST round-trip equivalence."""
    print("\n=== Round-Trip Equivalence Test ===\n")

    if not YARA_AVAILABLE:
        return

    # Original rules
    original_rules = """
    import "pe"

    rule round_trip_test {
        meta:
            author = "Test"
            version = 1.0

        strings:
            $a = "test" wide ascii
            $b = { 4D 5A [4-6] 50 45 00 00 }
            $c = /[a-z]+@[a-z]+\\.[a-z]+/i

        condition:
            any of ($a, $b) or
            $c and
            pe.is_pe
    }
    """

    parser = Parser()
    original_ast = parser.parse(original_rules)

    # Test round-trip
    tester = EquivalenceTester()
    result = tester.test_round_trip(original_ast)

    print(f"Round-trip result: {'PASSED' if result.equivalent else 'FAILED'}")
    print(f"  AST equivalent: {'✓' if result.ast_equivalent else '✗'}")
    print(f"  Code equivalent: {'✓' if result.code_equivalent else '✗'}")
    print(f"  Compiles (original): {'✓' if result.original_compiles else '✗'}")
    print(f"  Compiles (regenerated): {'✓' if result.regenerated_compiles else '✗'}")

    if result.ast_differences:
        print("\nAST differences found:")
        for diff in result.ast_differences:
            print(f"  - {diff}")


if __name__ == "__main__":
    example_compilation()
    example_scanning()
    example_cross_validation()
    example_round_trip()
