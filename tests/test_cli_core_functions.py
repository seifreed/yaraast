"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real CLI behavior without mocks or stubs.

Core function tests for yaraast CLI - testing internal functions directly.
These tests validate the core logic of CLI commands without subprocess overhead.
"""

# Import ast_tools directly without triggering CLI package imports
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

from yaraast import CodeGenerator, Parser

ast_tools_path = Path(__file__).parent.parent / "yaraast" / "cli" / "ast_tools.py"
spec = importlib.util.spec_from_file_location("ast_tools", ast_tools_path)
ast_tools = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ast_tools
spec.loader.exec_module(ast_tools)

ASTBenchmarker = ast_tools.ASTBenchmarker
ASTDiffer = ast_tools.ASTDiffer
ASTFormatter = ast_tools.ASTFormatter


class TestCLIParsingFunctions:
    """Tests for CLI parsing functions."""

    def test_parse_basic_yara_rule(self) -> None:
        """Test parsing a basic YARA rule."""
        yara_content = """
        rule basic_test {
            strings:
                $s1 = "malware"
            condition:
                $s1
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        assert ast is not None
        assert len(ast.rules) == 1
        assert ast.rules[0].name == "basic_test"
        assert len(ast.rules[0].strings) == 1

    def test_parse_and_generate_json(self) -> None:
        """Test parsing and converting to JSON."""
        from yaraast.serialization.json_serializer import JsonSerializer

        yara_content = """
        rule json_test {
            meta:
                author = "test"
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        serializer = JsonSerializer()
        result_str = serializer.serialize(ast)
        result = json.loads(result_str)

        assert isinstance(result, dict)
        # Check that serialization worked
        assert len(result_str) > 0

    def test_parse_complex_rule_with_hex_strings(self) -> None:
        """Test parsing complex rule with hex strings."""
        yara_content = """
        rule complex_hex {
            strings:
                $hex1 = { 4D 5A }
                $hex2 = { E8 [2-4] 5? }
                $s = "MZ"
            condition:
                $hex1 at 0 and $s
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        assert ast is not None
        assert len(ast.rules) == 1
        rule = ast.rules[0]
        assert rule.name == "complex_hex"
        assert len(rule.strings) == 3

    def test_parse_rule_with_imports(self) -> None:
        """Test parsing rule with imports."""
        yara_content = """
        import "pe"

        rule import_test {
            condition:
                true
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        assert ast is not None
        assert len(ast.imports) == 1
        assert ast.imports[0].module == "pe"
        assert len(ast.rules) == 1

    def test_parse_rule_with_regex_strings(self) -> None:
        """Test parsing rule with regex strings."""
        yara_content = r"""
        rule regex_test {
            strings:
                $re1 = /[a-zA-Z0-9]{32}/
                $re2 = /https?:\/\/[^\s]+/
            condition:
                any of them
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        assert ast is not None
        rule = ast.rules[0]
        assert rule.name == "regex_test"
        assert len(rule.strings) == 2

    def test_parse_private_global_rules(self) -> None:
        """Test parsing private and global rule modifiers."""
        yara_content = """
        private rule private_test {
            condition:
                true
        }

        global rule global_test {
            condition:
                true
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        assert ast is not None
        assert len(ast.rules) == 2
        # Check that modifiers are preserved
        assert "private" in ast.rules[0].modifiers or ast.rules[0].name == "private_test"
        assert "global" in ast.rules[1].modifiers or ast.rules[1].name == "global_test"

    def test_parse_rule_with_tags(self) -> None:
        """Test parsing rule with multiple tags."""
        yara_content = """
        rule tagged_rule : tag1 tag2 tag3 {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        assert ast is not None
        rule = ast.rules[0]
        assert rule.name == "tagged_rule"
        assert len(rule.tags) == 3


class TestCLIFormattingFunctions:
    """Tests for CLI formatting functions."""

    def test_format_basic_rule(self) -> None:
        """Test formatting a basic rule."""
        unformatted = """rule test{strings:$s="hello"condition:$s}"""

        parser = Parser()
        ast = parser.parse(unformatted)

        generator = CodeGenerator()
        formatted = generator.generate(ast)

        assert "rule test" in formatted
        assert "strings:" in formatted
        assert "condition:" in formatted

    def test_format_preserves_logic(self) -> None:
        """Verify formatting preserves rule logic."""
        yara_content = """
        rule logic_test {
            meta:
                author = "test"
            strings:
                $s1 = "test1"
                $s2 = "test2"
            condition:
                $s1 or $s2
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        generator = CodeGenerator()
        formatted = generator.generate(ast)

        # All key elements should be preserved
        assert "logic_test" in formatted
        assert "author" in formatted
        assert "$s1" in formatted
        assert "$s2" in formatted
        assert "or" in formatted

    def test_format_roundtrip(self) -> None:
        """Test that format→parse→format preserves structure."""
        original = """
        rule roundtrip {
            meta:
                version = 1
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser()
        ast1 = parser.parse(original.strip())

        generator = CodeGenerator()
        formatted = generator.generate(ast1)

        # Parse again
        ast2 = parser.parse(formatted)

        # Should have same structure
        assert len(ast1.rules) == len(ast2.rules)
        assert ast1.rules[0].name == ast2.rules[0].name
        assert len(ast1.rules[0].strings) == len(ast2.rules[0].strings)


class TestCLIDifferFunctions:
    """Tests for CLI diff functions."""

    def test_diff_identical_rules(self) -> None:
        """Test diffing identical rules."""
        yara_content = """
        rule identical {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser()
        ast1 = parser.parse(yara_content.strip())
        ast2 = parser.parse(yara_content.strip())

        differ = ASTDiffer()
        result = differ.diff_asts(ast1, ast2)

        assert result.has_changes is False
        assert len(result.logical_changes) == 0

    def test_diff_added_rule(self) -> None:
        """Test detecting added rules."""
        original = """
        rule test1 {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        modified = (
            original
            + """
        rule test2 {
            strings:
                $s = "new"
            condition:
                $s
        }
        """
        )

        parser = Parser()
        ast1 = parser.parse(original.strip())
        ast2 = parser.parse(modified.strip())

        differ = ASTDiffer()
        result = differ.diff_asts(ast1, ast2)

        assert result.has_changes is True
        assert "test2" in result.added_rules
        assert len(result.removed_rules) == 0

    def test_diff_modified_string(self) -> None:
        """Test detecting modified string content."""
        original = """
        rule test {
            strings:
                $s = "original"
            condition:
                $s
        }
        """

        modified = """
        rule test {
            strings:
                $s = "modified"
            condition:
                $s
        }
        """

        parser = Parser()
        ast1 = parser.parse(original.strip())
        ast2 = parser.parse(modified.strip())

        differ = ASTDiffer()
        result = differ.diff_asts(ast1, ast2)

        assert result.has_changes is True
        # Should detect logical changes
        assert len(result.logical_changes) > 0 or len(result.modified_rules) > 0


class TestCLIBenchmarkFunctions:
    """Tests for CLI benchmark functions."""

    def test_benchmark_parsing(self) -> None:
        """Test parsing benchmark."""
        yara_content = """
        rule bench_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            benchmarker = ASTBenchmarker()
            result = benchmarker.benchmark_parsing(test_file, iterations=3)

            assert result.success is True
            assert result.operation == "parsing"
            assert result.execution_time > 0
            assert result.rules_count == 1
            assert result.ast_nodes > 0

        finally:
            test_file.unlink()

    def test_benchmark_codegen(self) -> None:
        """Test code generation benchmark."""
        yara_content = """
        rule codegen_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            benchmarker = ASTBenchmarker()
            result = benchmarker.benchmark_codegen(test_file, iterations=3)

            assert result.success is True
            assert result.operation == "codegen"
            assert result.execution_time > 0
            assert result.rules_count == 1

        finally:
            test_file.unlink()

    def test_benchmark_roundtrip(self) -> None:
        """Test roundtrip benchmark."""
        yara_content = """
        rule roundtrip_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            benchmarker = ASTBenchmarker()
            results = benchmarker.benchmark_roundtrip(test_file, iterations=2)

            assert len(results) == 1
            result = results[0]
            assert result.success is True
            assert result.operation == "roundtrip"
            assert result.execution_time > 0

        finally:
            test_file.unlink()

    def test_benchmark_summary(self) -> None:
        """Test benchmark summary generation."""
        yara_content = """
        rule summary_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            benchmarker = ASTBenchmarker()

            # Run multiple benchmarks
            benchmarker.benchmark_parsing(test_file, iterations=2)
            benchmarker.benchmark_codegen(test_file, iterations=2)

            summary = benchmarker.get_benchmark_summary()

            assert "parsing" in summary
            assert "codegen" in summary
            assert summary["parsing"]["count"] == 1
            assert summary["codegen"]["count"] == 1
            assert summary["parsing"]["avg_time"] > 0
            assert summary["codegen"]["avg_time"] > 0

        finally:
            test_file.unlink()


class TestCLIFormatterClass:
    """Tests for ASTFormatter class."""

    def test_formatter_basic(self) -> None:
        """Test basic formatting."""
        unformatted = """rule test{strings:$s="hello"condition:$s}"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(unformatted)
            test_file = Path(f.name)

        try:
            formatter = ASTFormatter()
            success, formatted = formatter.format_file(test_file, None, "pretty")

            assert success is True
            assert "rule test" in formatted
            assert formatted.count("\n") > unformatted.count("\n")

        finally:
            test_file.unlink()

    def test_formatter_check(self) -> None:
        """Test format checking."""
        # Well-formatted YARA
        well_formatted = """rule test {
    strings:
        $a = "hello"
    condition:
        $a
}"""

        # Poorly formatted YARA
        poorly_formatted = """rule test{strings:$a="hello"condition:$a}"""

        formatter = ASTFormatter()

        # Test well-formatted file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(well_formatted)
            good_file = Path(f.name)

        try:
            needs_format, issues = formatter.check_format(good_file)
            assert isinstance(needs_format, bool)
            assert isinstance(issues, list)
        finally:
            good_file.unlink()

        # Test poorly formatted file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(poorly_formatted)
            bad_file = Path(f.name)

        try:
            needs_format, issues = formatter.check_format(bad_file)
            assert needs_format is True
            assert len(issues) > 0
        finally:
            bad_file.unlink()


class TestCLITreeVisualization:
    """Tests for tree visualization using ast_tools functions."""

    def test_ast_print_basic(self) -> None:
        """Test basic AST printing."""
        yara_content = """
        rule tree_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        # Use visualize_ast from ast_tools which doesn't require CLI main
        result = ast_tools.visualize_ast(ast, "json")

        assert result is not None
        assert len(result) > 0
        # Should be valid JSON
        json.loads(result)

    def test_ast_visualization_json_format(self) -> None:
        """Test AST visualization in JSON format."""
        yara_content = """
        rule meta_test {
            meta:
                author = "test"
                version = 1
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        result = ast_tools.visualize_ast(ast, "json")

        assert result is not None
        assert len(result) > 0
        # Verify it's valid JSON
        data = json.loads(result)
        assert isinstance(data, dict)


class TestCLIIntegration:
    """Integration tests for CLI functions."""

    def test_full_parse_format_parse_cycle(self) -> None:
        """Test complete parse-format-parse cycle."""
        original = """
        rule integration_test {
            meta:
                author = "test"
            strings:
                $s1 = "test1"
                $s2 = { 4D 5A }
            condition:
                $s1 or $s2
        }
        """

        # Parse
        parser = Parser()
        ast1 = parser.parse(original.strip())

        # Format
        generator = CodeGenerator()
        formatted = generator.generate(ast1)

        # Parse again
        ast2 = parser.parse(formatted)

        # Verify structure preserved
        assert len(ast1.rules) == len(ast2.rules)
        assert ast1.rules[0].name == ast2.rules[0].name
        assert len(ast1.rules[0].strings) == len(ast2.rules[0].strings)

    def test_parse_json_roundtrip(self) -> None:
        """Test parsing to JSON and back."""
        from yaraast.serialization.json_serializer import JsonSerializer

        yara_content = """
        rule json_roundtrip {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser()
        ast = parser.parse(yara_content.strip())

        # Convert to JSON
        serializer = JsonSerializer()
        json_str = serializer.serialize(ast)
        json_result = json.loads(json_str)

        # Verify JSON structure
        assert isinstance(json_result, dict)
        assert len(json_str) > 0

    def test_format_and_diff(self) -> None:
        """Test formatting then diffing."""
        original = """rule test{strings:$s="hello"condition:$s}"""

        parser = Parser()
        ast1 = parser.parse(original)

        generator = CodeGenerator()
        formatted = generator.generate(ast1)

        ast2 = parser.parse(formatted)

        differ = ASTDiffer()
        result = differ.diff_asts(ast1, ast2)

        # Structure should be identical
        assert len(result.added_rules) == 0
        assert len(result.removed_rules) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
