"""Test YARA-X compatibility features."""

from yaraast.parser import Parser
from yaraast.yarax import YaraXCompatibilityChecker, YaraXFeatures, YaraXSyntaxAdapter


def test_regex_brace_escaping() -> None:
    """Test detection of unescaped braces in regex."""
    yara_code = """
rule regex_test {
    strings:
        $a = /abc{/          // Unescaped brace
        $b = /abc\\{/        // Properly escaped
        $c = /a{3,5}/        // Valid quantifier
        $d = /{start/        // Unescaped at start

    condition:
        any of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    checker = YaraXCompatibilityChecker()
    issues = checker.check(ast)

    # Should find unescaped braces
    unescaped = [i for i in issues if i.issue_type == "unescaped_brace"]
    assert len(unescaped) >= 2


def test_invalid_escape_sequences() -> None:
    """Test detection of invalid escape sequences."""
    yara_code = """
rule escape_test {
    strings:
        $a = /\\g/           // Invalid escape
        $b = /\\n/           // Valid escape
        $c = /\\k/           // Invalid escape
        $d = /\\x41/         // Valid hex escape

    condition:
        any of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    checker = YaraXCompatibilityChecker()
    issues = checker.check(ast)

    # Should find invalid escapes
    invalid = [i for i in issues if i.issue_type == "invalid_escape"]
    assert len(invalid) >= 2


def test_base64_length_validation() -> None:
    """Test base64 pattern length validation."""
    yara_code = """
rule base64_test {
    strings:
        $a = "AB" base64      // Too short for YARA-X
        $b = "ABC" base64     // Minimum length
        $c = "ABCD" base64    // OK

    condition:
        any of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    checker = YaraXCompatibilityChecker()
    issues = checker.check(ast)

    # Should find too-short base64 pattern
    short_base64 = [i for i in issues if i.issue_type == "base64_too_short"]
    assert len(short_base64) >= 1


def test_duplicate_modifiers() -> None:
    """Test detection of duplicate rule modifiers."""
    yara_code = """
private private rule dup_test1 {
    condition: true
}

global global rule dup_test2 {
    condition: true
}

private global rule ok_test {
    condition: true
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    checker = YaraXCompatibilityChecker()
    issues = checker.check(ast)

    # Should find duplicate modifiers
    duplicates = [i for i in issues if i.issue_type == "duplicate_modifier"]
    assert len(duplicates) >= 2


def test_syntax_adaptation() -> None:
    """Test YARA to YARA-X syntax adaptation."""
    yara_code = """
rule adapt_me {
    strings:
        $a = /abc{/          // Needs escaping
        $b = "A" base64      // Needs padding

    condition:
        all of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    adapter = YaraXSyntaxAdapter(target="yarax")
    adapted, count = adapter.adapt(ast)

    # Should have adaptations
    assert count > 0

    # Check adaptations were applied
    from yaraast.codegen import CodeGenerator

    generator = CodeGenerator()
    output = generator.generate(adapted)

    # Regex should be escaped
    assert "abc\\{" in output or "abc{" not in output

    # Base64 string should be padded
    assert '"AAA" base64' in output or '"A" base64' not in output


def test_compatibility_report() -> None:
    """Test comprehensive compatibility report."""
    yara_code = """
private private rule complex_test {
    strings:
        $a = /test{/
        $b = /\\g/
        $c = "A" base64
        $d = "test" xor fullword

    condition:
        any of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    checker = YaraXCompatibilityChecker()
    checker.check(ast)
    report = checker.get_report()

    # Check report structure
    assert "compatible" in report
    assert report["compatible"] is False  # Should have errors
    assert report["errors"] > 0
    assert "migration_difficulty" in report
    assert report["migration_difficulty"] in ["easy", "moderate", "difficult"]


def test_migration_guide_generation() -> None:
    """Test migration guide generation."""
    yara_code = """
rule migration_test {
    strings:
        $a = /pattern{/
        $b = /test\\g/
        $c = "AB" base64

    condition:
        all of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    checker = YaraXCompatibilityChecker()
    issues = checker.check(ast)

    adapter = YaraXSyntaxAdapter()
    guide = adapter.generate_migration_guide(issues)

    # Should contain migration instructions
    assert "Migration Guide" in guide
    assert "Regex Brace Escaping" in guide or "regex" in guide.lower()
    assert "Base64 Pattern Length" in guide or "base64" in guide.lower()


def test_yara_compatibility_mode() -> None:
    """Test YARA compatibility mode."""
    features = YaraXFeatures.yara_compatible()

    # All strict features should be disabled
    assert not features.strict_regex_escaping
    assert not features.validate_escape_sequences
    assert features.minimum_base64_length == 0
    assert not features.allow_with_statement

    # Test with checker
    yara_code = """
rule yara_compat {
    strings:
        $a = /test{/    // Should not error in YARA mode

    condition:
        $a
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    checker = YaraXCompatibilityChecker(features)
    issues = checker.check(ast)

    # Should have no errors in YARA compatibility mode
    errors = [i for i in issues if i.severity == "error"]
    assert len(errors) == 0


if __name__ == "__main__":
    test_regex_brace_escaping()
    test_invalid_escape_sequences()
    test_base64_length_validation()
    test_duplicate_modifiers()
    test_syntax_adaptation()
    test_compatibility_report()
    test_migration_guide_generation()
    test_yara_compatibility_mode()
    print("✓ All YARA-X compatibility tests passed")
