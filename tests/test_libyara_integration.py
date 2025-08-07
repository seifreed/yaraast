"""Tests for libyara integration with direct AST compilation."""

import tempfile
from pathlib import Path

import pytest

try:
    import yara  # noqa: F401

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from yaraast.parser import Parser, YaraParser

if YARA_AVAILABLE:
    from yaraast.libyara import (
        DirectASTCompiler,
        EquivalenceTester,
        LibyaraCompiler,
        LibyaraScanner,
        OptimizedMatcher,
    )
    from yaraast.libyara.cross_validator import CrossValidator


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
class TestDirectASTCompiler:
    """Tests for direct AST compilation."""

    def test_basic_compilation(self) -> None:
        """Test basic AST compilation to yara.Rules."""
        yara_source = """
        rule test_rule {
            strings:
                $a = "hello"
                $b = { 4D 5A }
            condition:
                $a and $b
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        compiler = DirectASTCompiler()
        result = compiler.compile_ast(ast)

        assert result.success is True
        assert result.compiled_rules is not None
        assert len(result.errors) == 0
        assert result.compilation_time > 0
        assert result.ast_node_count > 0

    def test_compilation_with_optimization(self) -> None:
        """Test compilation with AST optimizations."""
        yara_source = """
        rule test_rule {
            strings:
                $used = "hello"
                $unused = "world"  // This should be optimized away
            condition:
                $used
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        compiler = DirectASTCompiler(enable_optimization=True)
        result = compiler.compile_ast(ast)

        assert result.success is True
        assert result.optimized is True
        assert result.optimization_stats is not None
        assert result.optimization_stats.strings_optimized > 0


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
class TestOptimizedMatcher:
    """Tests for optimized matcher."""

    def test_basic_scanning(self) -> None:
        """Test basic file scanning with optimized matcher."""
        yara_source = """
        rule scan_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        # Create test file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("This is a test file with the word test in it.")
            test_file = Path(f.name)

        try:
            parser = YaraParser()
            ast = parser.parse(yara_source.strip())

            # Compile rules
            compiler = DirectASTCompiler()
            compile_result = compiler.compile_ast(ast)
            assert compile_result.success is True

            # Create matcher
            matcher = OptimizedMatcher(compile_result.compiled_rules, ast)

            # Scan file
            scan_result = matcher.scan(test_file)

            assert scan_result["success"] is True
            assert len(scan_result["matches"]) == 1
            assert scan_result["matches"][0]["rule"] == "scan_test"
            assert scan_result["ast_enhanced"] is True

        finally:
            test_file.unlink()


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
class TestLibyaraCompiler:
    """Test libyara compiler (legacy compatibility)."""

    def test_compile_simple_rule(self) -> None:
        """Test compiling a simple rule."""
        rule_text = """
        rule test_rule {
            strings:
                $a = "hello"
            condition:
                $a
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        compiler = LibyaraCompiler()
        result = compiler.compile_ast(ast)

        assert result.success is True
        assert result.compiled_rules is not None
        assert len(result.errors) == 0

    def test_compile_with_imports(self) -> None:
        """Test compiling with module imports."""
        rule_text = """
        import "pe"

        rule test_pe {
            condition:
                pe.is_pe
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        compiler = LibyaraCompiler()
        result = compiler.compile_ast(ast)

        # This should compile successfully
        assert result.success is True

    def test_compile_syntax_error(self) -> None:
        """Test compilation with syntax error."""
        # Directly compile invalid source
        compiler = LibyaraCompiler()
        result = compiler.compile_source("rule { condition: invalid }")

        assert result.success is False
        assert len(result.errors) > 0

    def test_compile_with_externals(self) -> None:
        """Test compilation with external variables."""
        rule_text = """
        rule test_external {
            condition:
                ext_var == "test"
        }
        """

        compiler = LibyaraCompiler(externals={"ext_var": "test"})
        result = compiler.compile_source(rule_text)

        assert result.success is True


class TestLibyaraScanner:
    """Test libyara scanner."""

    def test_scan_matching_data(self) -> None:
        """Test scanning data that matches."""
        rule_text = """
        rule test_match {
            strings:
                $a = "hello"
            condition:
                $a
        }
        """

        compiler = LibyaraCompiler()
        compilation = compiler.compile_source(rule_text)
        assert compilation.success

        scanner = LibyaraScanner()
        result = scanner.scan_data(compilation.compiled_rules, b"hello world")

        assert result.success is True
        assert result.matched is True
        assert "test_match" in result.matched_rules

    def test_scan_non_matching_data(self) -> None:
        """Test scanning data that doesn't match."""
        rule_text = """
        rule test_no_match {
            strings:
                $a = "xyz"
            condition:
                $a
        }
        """

        compiler = LibyaraCompiler()
        compilation = compiler.compile_source(rule_text)
        assert compilation.success

        scanner = LibyaraScanner()
        result = scanner.scan_data(compilation.compiled_rules, b"hello world")

        assert result.success is True
        assert result.matched is False
        assert len(result.matched_rules) == 0

    def test_scan_with_timeout(self) -> None:
        """Test scanning with timeout."""
        rule_text = """
        rule test_rule {
            condition:
                true
        }
        """

        compiler = LibyaraCompiler()
        compilation = compiler.compile_source(rule_text)

        # Very short timeout shouldn't affect simple scan
        scanner = LibyaraScanner(timeout=10)
        result = scanner.scan_data(compilation.compiled_rules, b"test")

        assert result.success is True


class TestEquivalenceTester:
    """Test AST equivalence testing."""

    def test_simple_round_trip(self) -> None:
        """Test simple AST round-trip."""
        rule_text = """
        rule test_rule {
            strings:
                $a = "test"
                $b = { 48 65 6c 6c 6f }
            condition:
                $a or $b
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        tester = EquivalenceTester()
        result = tester.test_round_trip(ast, test_data=b"test hello")

        assert result.equivalent is True
        assert result.ast_equivalent is True
        assert result.code_equivalent is True
        assert result.original_compiles is True
        assert result.regenerated_compiles is True

    def test_complex_round_trip(self) -> None:
        """Test complex rule round-trip."""
        rule_text = """
        import "pe"

        rule complex_rule {
            meta:
                author = "test"
                version = 1
            strings:
                $mz = { 4D 5A }
                $str = "This program"
            condition:
                $mz at 0 and
                $str and
                pe.is_pe and
                filesize > 100
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        tester = EquivalenceTester()

        # Create test PE data
        pe_data = b"MZ" + b"\x00" * 200
        result = tester.test_round_trip(ast, test_data=pe_data)

        # Check compilation works
        assert result.original_compiles is True
        assert result.regenerated_compiles is True

        # AST should be equivalent
        assert result.ast_equivalent is True


class TestCrossValidator:
    """Test cross-validation between yaraast and libyara."""

    def test_simple_validation(self) -> None:
        """Test simple rule validation."""
        rule_text = """
        rule test_rule {
            strings:
                $a = "hello"
            condition:
                $a
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        validator = CrossValidator()

        # Test matching data
        result = validator.validate(ast, b"hello world")

        assert result.valid is True
        assert result.rules_tested == 1
        assert result.rules_matched == 1
        assert result.yaraast_results["test_rule"] is True
        assert result.libyara_results["test_rule"] is True

    def test_validation_mismatch(self) -> None:
        """Test when yaraast and libyara disagree."""
        # This is a synthetic test - in practice they should agree
        # We'll test with a complex condition to ensure both work
        rule_text = """
        rule test_complex {
            strings:
                $a = "test"
                $b = { 41 42 43 }
            condition:
                #a > 1 or $b at 0
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        validator = CrossValidator()

        # Test with data containing multiple "test"
        result = validator.validate(ast, b"test this test ABC")

        assert result.valid is True
        assert result.yaraast_results["test_complex"] is True
        assert result.libyara_results["test_complex"] is True

    def test_batch_validation(self) -> None:
        """Test batch validation."""
        rule_text = """
        rule test_rule {
            strings:
                $a = "mal"
            condition:
                $a
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        validator = CrossValidator()

        test_samples = [b"malware", b"normal file", b"malicious", b"benign"]

        results = validator.validate_batch(ast, test_samples)

        assert len(results) == 4
        assert results[0].valid is True  # "malware" matches
        assert results[0].yaraast_results["test_rule"] is True
        assert results[1].valid is True  # "normal file" doesn't match
        assert results[1].yaraast_results["test_rule"] is False
        assert results[2].valid is True  # "malicious" matches
        assert results[2].yaraast_results["test_rule"] is True
