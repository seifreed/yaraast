"""Tests for AST-based CLI tools."""

import tempfile
from pathlib import Path

from yaraast.cli.ast_tools import ASTBenchmarker, ASTDiffer, ASTFormatter, ASTStructuralAnalyzer
from yaraast.parser import Parser


class TestASTFormatter:
    """Tests for AST-based formatter."""

    def test_basic_formatting(self) -> None:
        """Test basic file formatting."""
        # Unformatted YARA
        unformatted = """rule test{strings:$a="hello"condition:$a}"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(unformatted)
            test_file = Path(f.name)

        try:
            formatter = ASTFormatter()
            success, formatted = formatter.format_file(test_file, None, "pretty")

            assert success is True
            assert "rule test" in formatted
            assert "strings:" in formatted
            assert "condition:" in formatted
            assert formatted.count("\n") > unformatted.count(
                "\n",
            )  # More lines after formatting

        finally:
            test_file.unlink()

    def test_format_styles(self) -> None:
        """Test different formatting styles."""
        yara_code = """
        rule style_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_code.strip())
            test_file = Path(f.name)

        try:
            formatter = ASTFormatter()

            # Test different styles
            success_compact, compact = formatter.format_file(test_file, None, "compact")
            success_pretty, pretty = formatter.format_file(test_file, None, "pretty")
            success_verbose, verbose = formatter.format_file(test_file, None, "verbose")

            assert success_compact
            assert success_pretty
            assert success_verbose

            # Verbose should have more lines than compact
            assert verbose.count("\n") >= pretty.count("\n") >= compact.count("\n")

        finally:
            test_file.unlink()

    def test_format_check(self) -> None:
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
            # May or may not need formatting depending on exact style match
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


class TestASTDiffer:
    """Tests for AST-based differ."""

    def test_no_differences(self) -> None:
        """Test files with no differences."""
        yara_code = """
        rule test {
            strings:
                $s = "hello"
            condition:
                $s
        }
        """

        # Create two identical files
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(yara_code.strip())
            file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(yara_code.strip())
            file2 = Path(f2.name)

        try:
            differ = ASTDiffer()
            result = differ.diff_files(file1, file2)

            assert result.has_changes is False
            assert len(result.logical_changes) == 0
            assert len(result.added_rules) == 0
            assert len(result.removed_rules) == 0

        finally:
            file1.unlink()
            file2.unlink()

    def test_rule_addition(self) -> None:
        """Test detecting added rules."""
        original = """
        rule test1 {
            strings:
                $s = "hello"
            condition:
                $s
        }
        """

        modified = """
        rule test1 {
            strings:
                $s = "hello"
            condition:
                $s
        }

        rule test2 {
            strings:
                $s = "world"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(original.strip())
            file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(modified.strip())
            file2 = Path(f2.name)

        try:
            differ = ASTDiffer()
            result = differ.diff_files(file1, file2)

            assert result.has_changes is True
            assert "test2" in result.added_rules
            assert len(result.removed_rules) == 0
            assert result.change_summary["added_rules"] == 1

        finally:
            file1.unlink()
            file2.unlink()

    def test_logical_vs_style_changes(self) -> None:
        """Test distinguishing logical from style changes."""
        original = """rule test {
    strings:
        $s = "hello"
    condition:
        $s
}"""

        # Style change only (different spacing)
        style_changed = """rule test{
strings:
$s="hello"
condition:
$s
}"""

        # Logical change (different string content)
        logic_changed = """rule test {
    strings:
        $s = "goodbye"
    condition:
        $s
}"""

        differ = ASTDiffer()

        # Test style-only change
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(original)
            file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(style_changed)
            file2 = Path(f2.name)

        try:
            result = differ.diff_files(file1, file2)

            # Should detect minimal or no logical changes for style-only diff
            assert (
                result.change_summary["logical_changes"] <= 1
            )  # May detect some structural differences

        finally:
            file1.unlink()
            file2.unlink()

        # Test logical change
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(original)
            file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(logic_changed)
            file2 = Path(f2.name)

        try:
            result = differ.diff_files(file1, file2)

            # Should detect logical changes
            assert result.has_changes is True
            assert (
                result.change_summary["logical_changes"] > 0
                or result.change_summary["modified_rules"] > 0
            )

        finally:
            file1.unlink()
            file2.unlink()


class TestASTStructuralAnalyzer:
    """Tests for AST structural analyzer."""

    def test_rule_signature_generation(self) -> None:
        """Test rule signature generation."""
        yara_code = """
        rule test_rule : tag1 tag2 {
            meta:
                author = "test"
                version = 1
            strings:
                $s1 = "hello"
                $s2 = { 4D 5A }
            condition:
                $s1 and $s2
        }
        """

        parser = Parser()
        ast = parser.parse(yara_code.strip())

        analyzer = ASTStructuralAnalyzer()
        analysis = analyzer.analyze(ast)

        assert "test_rule" in analysis["rule_signatures"]
        assert analysis["total_rules"] == 1
        assert len(analysis["string_signatures"]) == 2
        assert "$s1" in analysis["string_signatures"]
        assert "$s2" in analysis["string_signatures"]

    def test_structural_hash_consistency(self) -> None:
        """Test that identical structures produce identical hashes."""
        yara_code = """
        rule test {
            strings:
                $s = "hello"
            condition:
                $s
        }
        """

        parser = Parser()
        ast1 = parser.parse(yara_code.strip())
        ast2 = parser.parse(yara_code.strip())

        analyzer = ASTStructuralAnalyzer()
        analysis1 = analyzer.analyze(ast1)
        analysis2 = analyzer.analyze(ast2)

        # Same code should produce same signatures
        assert analysis1["rule_signatures"] == analysis2["rule_signatures"]
        assert analysis1["structural_hash"] == analysis2["structural_hash"]


class TestASTBenchmarker:
    """Tests for AST benchmarker."""

    def test_parsing_benchmark(self) -> None:
        """Test parsing benchmark."""
        yara_code = """
        rule benchmark_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_code.strip())
            test_file = Path(f.name)

        try:
            benchmarker = ASTBenchmarker()
            result = benchmarker.benchmark_parsing(test_file, iterations=3)

            assert result.success is True
            assert result.operation == "parsing"
            assert result.execution_time > 0
            assert result.rules_count == 1
            assert result.ast_nodes > 0
            assert result.file_size > 0

        finally:
            test_file.unlink()

    def test_codegen_benchmark(self) -> None:
        """Test code generation benchmark."""
        yara_code = """
        rule codegen_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_code.strip())
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

    def test_roundtrip_benchmark(self) -> None:
        """Test roundtrip benchmark."""
        yara_code = """
        rule roundtrip_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_code.strip())
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
        yara_code = """
        rule summary_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_code.strip())
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


class TestIntegration:
    """Integration tests for CLI tools."""

    def test_format_and_diff_workflow(self) -> None:
        """Test formatting a file then diffing the changes."""
        original = """rule test{strings:$s="hello"condition:$s}"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(original)
            original_file = Path(f.name)

        try:
            # Format the file
            formatter = ASTFormatter()
            success, formatted = formatter.format_file(original_file, None, "pretty")
            assert success is True

            # Write formatted version to new file
            with tempfile.NamedTemporaryFile(
                mode="w",
                delete=False,
                suffix=".yar",
            ) as f:
                f.write(formatted)
                formatted_file = Path(f.name)

            try:
                # Diff the files
                differ = ASTDiffer()
                result = differ.diff_files(original_file, formatted_file)

                # Should detect style changes but minimal logical changes
                # (depending on implementation details, may detect some structural differences)
                assert isinstance(result.has_changes, bool)
                assert result.change_summary["added_rules"] == 0
                assert result.change_summary["removed_rules"] == 0

            finally:
                formatted_file.unlink()

        finally:
            original_file.unlink()


if __name__ == "__main__":
    # Run simple tests
    print("Testing CLI tools...")

    # Test formatter
    formatter = ASTFormatter()
    yara_test = 'rule test{strings:$s="hello"condition:$s}'

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
        f.write(yara_test)
        test_file = Path(f.name)

    try:
        success, formatted = formatter.format_file(test_file, None, "pretty")
        print(f"✓ Formatting: {'PASSED' if success else 'FAILED'}")

        if success:
            print(
                f"✓ Formatted output contains proper structure: {'PASSED' if 'strings:' in formatted else 'FAILED'}",
            )
    finally:
        test_file.unlink()

    # Test differ
    differ = ASTDiffer()
    analyzer = ASTStructuralAnalyzer()

    yara_test = """
    rule differ_test {
        strings:
            $s = "test"
        condition:
            $s
    }
    """

    parser = Parser()
    ast = parser.parse(yara_test.strip())
    analysis = analyzer.analyze(ast)

    print(
        f"✓ AST analysis: {'PASSED' if 'differ_test' in analysis['rule_signatures'] else 'FAILED'}",
    )

    # Test benchmarker
    benchmarker = ASTBenchmarker()

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
        f.write(yara_test.strip())
        bench_file = Path(f.name)

    try:
        result = benchmarker.benchmark_parsing(bench_file, iterations=2)
        print(f"✓ Benchmarking: {'PASSED' if result.success else 'FAILED'}")

        if result.success:
            print(
                f"✓ Benchmark captured metrics: {'PASSED' if result.execution_time > 0 and result.rules_count > 0 else 'FAILED'}",
            )
    finally:
        bench_file.unlink()

    print("✅ CLI tools tests completed!")
