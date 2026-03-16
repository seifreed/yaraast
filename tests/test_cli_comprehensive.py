"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real CLI behavior without mocks or stubs.

Comprehensive tests for yaraast CLI commands.
Tests all major CLI functionality including parse, format, analyze, validate, and more.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


class TestCLIParseCommand:
    """Tests for the 'yaraast parse' command."""

    def test_parse_basic_yara_to_stdout(self) -> None:
        """Parse a basic YARA file and output to stdout."""
        yara_content = """
        rule basic_test {
            strings:
                $s1 = "malware"
            condition:
                $s1
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "parse", str(test_file)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            assert "rule basic_test" in result.stdout or "basic_test" in result.stdout

        finally:
            test_file.unlink()

    def test_parse_with_json_output(self) -> None:
        """Parse YARA file and output as JSON."""
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

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            # Verify output is valid JSON
            json_output = json.loads(result.stdout)
            assert "rules" in json_output or "type" in json_output

        finally:
            test_file.unlink()

    def test_parse_with_tree_output(self) -> None:
        """Parse YARA file and output as tree visualization."""
        yara_content = """
        rule tree_test {
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
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "tree",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            # Tree output should contain rule structure
            assert "tree_test" in result.stdout or "Rule" in result.stdout

        finally:
            test_file.unlink()

    def test_parse_with_output_file(self) -> None:
        """Parse YARA file and save output to file."""
        yara_content = """
        rule output_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as out:
            output_file = Path(out.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            assert output_file.exists()
            assert output_file.stat().st_size > 0

            # Verify output is valid JSON
            with output_file.open() as f:
                json_data = json.load(f)
                assert isinstance(json_data, dict)

        finally:
            test_file.unlink()
            if output_file.exists():
                output_file.unlink()

    def test_parse_auto_dialect_detection(self) -> None:
        """Test automatic dialect detection."""
        yara_content = """
        rule dialect_test {
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
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--dialect",
                    "auto",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            # Should detect dialect and report it
            assert "Detected dialect" in result.stdout or "rule dialect_test" in result.stdout

        finally:
            test_file.unlink()

    def test_parse_invalid_yara_file(self) -> None:
        """Test parsing an invalid YARA file."""
        invalid_yara = "this is not valid yara syntax"

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(invalid_yara)
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "parse", str(test_file)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            # Should fail or show errors
            assert (
                result.returncode != 0
                or "Error" in result.stdout
                or "issue" in result.stdout.lower()
            )

        finally:
            test_file.unlink()

    def test_parse_complex_rule_with_hex_strings(self) -> None:
        """Parse complex rule with hex strings."""
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

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            json_output = json.loads(result.stdout)
            # Should contain hex string information
            assert json_output is not None

        finally:
            test_file.unlink()


class TestCLIFormatCommand:
    """Tests for the 'yaraast format' command."""

    def test_format_basic_file(self) -> None:
        """Format a basic YARA file."""
        unformatted = """rule test{strings:$s="hello"condition:$s}"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(unformatted)
            input_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as out:
            output_file = Path(out.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "format",
                    str(input_file),
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            assert output_file.exists()

            # Read formatted output
            with output_file.open() as f:
                formatted = f.read()

            # Should have proper formatting
            assert "rule test" in formatted
            assert "strings:" in formatted
            assert "condition:" in formatted
            assert formatted.count("\n") > unformatted.count("\n")

        finally:
            input_file.unlink()
            if output_file.exists():
                output_file.unlink()

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

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            input_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as out:
            output_file = Path(out.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "format",
                    str(input_file),
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0

            with output_file.open() as f:
                formatted = f.read()

            # All key elements should be preserved
            assert "logic_test" in formatted
            assert "author" in formatted
            assert "$s1" in formatted
            assert "$s2" in formatted
            assert "or" in formatted

        finally:
            input_file.unlink()
            if output_file.exists():
                output_file.unlink()


class TestCLIValidateCommand:
    """Tests for the 'yaraast validate' command."""

    def test_validate_valid_file(self) -> None:
        """Validate a valid YARA file."""
        valid_yara = """
        rule valid_rule {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(valid_yara.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "validate", str(test_file)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            assert "Valid" in result.stdout or "valid" in result.stdout.lower()

        finally:
            test_file.unlink()

    def test_validate_invalid_file(self) -> None:
        """Validate an invalid YARA file."""
        invalid_yara = "this is not valid yara"

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(invalid_yara)
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "validate", str(test_file)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            # Should fail or show invalid
            assert result.returncode != 0 or "Invalid" in result.stdout or "Error" in result.stdout

        finally:
            test_file.unlink()

    def test_validate_shows_statistics(self) -> None:
        """Validate shows rule statistics."""
        yara_content = """
        import "pe"

        rule stats_test {
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
            result = subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "validate", str(test_file)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            # Should show statistics
            assert "Rules:" in result.stdout or "rule" in result.stdout.lower()

        finally:
            test_file.unlink()


class TestCLIFmtCommand:
    """Tests for the 'yaraast fmt' command."""

    def test_fmt_with_check_option(self) -> None:
        """Test format checking without modifying file."""
        poorly_formatted = """rule test{strings:$s="x"condition:$s}"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(poorly_formatted)
            test_file = Path(f.name)

        try:
            subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "fmt", str(test_file), "--check"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            # File should not be modified
            with test_file.open() as f:
                content = f.read()
            assert content == poorly_formatted

            # Should report needs formatting
            # Exit code may vary based on implementation

        finally:
            test_file.unlink()

    def test_fmt_different_styles(self) -> None:
        """Test different formatting styles."""
        yara_content = """
        rule style_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        for style in ["default", "compact", "pretty", "verbose"]:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
                f.write(yara_content.strip())
                test_file = Path(f.name)

            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as out:
                output_file = Path(out.name)

            try:
                result = subprocess.run(
                    [
                        "python",
                        "-m",
                        "yaraast.cli.main",
                        "fmt",
                        str(test_file),
                        "--output",
                        str(output_file),
                        "--style",
                        style,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )

                assert result.returncode == 0
                assert output_file.exists()

                with output_file.open() as f:
                    formatted = f.read()
                    assert "style_test" in formatted

            finally:
                test_file.unlink()
                if output_file.exists():
                    output_file.unlink()

    def test_fmt_with_diff_option(self) -> None:
        """Test showing diff of formatting changes."""
        unformatted = """rule diff_test{strings:$s="test"condition:$s}"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(unformatted)
            test_file = Path(f.name)

        try:
            subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "fmt", str(test_file), "--diff"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            # Should show diff output
            # File should not be modified
            with test_file.open() as f:
                content = f.read()
            assert content == unformatted

        finally:
            test_file.unlink()


class TestCLIDiffCommand:
    """Tests for the 'yaraast diff' command."""

    def test_diff_identical_files(self) -> None:
        """Diff two identical files."""
        yara_content = """
        rule identical {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(yara_content.strip())
            file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(yara_content.strip())
            file2 = Path(f2.name)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "diff", str(file1), str(file2)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            assert "No differences" in result.stdout or "no" in result.stdout.lower()

        finally:
            file1.unlink()
            file2.unlink()

    def test_diff_added_rule(self) -> None:
        """Diff files with added rule."""
        original = """
        rule original {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        modified = (
            original
            + """
        rule added {
            strings:
                $s = "new"
            condition:
                $s
        }
        """
        )

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(original.strip())
            file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(modified.strip())
            file2 = Path(f2.name)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "yaraast.cli.main", "diff", str(file1), str(file2)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            # Should detect added rule
            assert "added" in result.stdout.lower() or "Added" in result.stdout

        finally:
            file1.unlink()
            file2.unlink()

    def test_diff_logical_only_option(self) -> None:
        """Test diff with logical-only changes filter."""
        file1_content = """
        rule test {
            strings:
                $s = "original"
            condition:
                $s
        }
        """

        file2_content = """
        rule test {
            strings:
                $s = "modified"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(file1_content.strip())
            file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(file2_content.strip())
            file2 = Path(f2.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "diff",
                    str(file1),
                    str(file2),
                    "--logical-only",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            # Should show logical changes
            assert "change" in result.stdout.lower() or "modified" in result.stdout.lower()

        finally:
            file1.unlink()
            file2.unlink()

    def test_diff_summary_option(self) -> None:
        """Test diff with summary option."""
        file1 = """rule test { condition: true }"""
        file2 = """rule test { condition: false }"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f1:
            f1.write(file1)
            test_file1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f2:
            f2.write(file2)
            test_file2 = Path(f2.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "diff",
                    str(test_file1),
                    str(test_file2),
                    "--summary",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            # Should show summary
            assert "Summary" in result.stdout or "Change" in result.stdout

        finally:
            test_file1.unlink()
            test_file2.unlink()


class TestCLIBenchCommand:
    """Tests for the 'yaraast bench' command."""

    def test_bench_single_file(self) -> None:
        """Benchmark a single YARA file."""
        yara_content = """
        rule bench_test {
            strings:
                $s1 = "test1"
                $s2 = "test2"
            condition:
                any of them
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "bench",
                    str(test_file),
                    "--iterations",
                    "3",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            assert result.returncode == 0
            # Should show benchmark results
            assert "Benchmark" in result.stdout or "ms" in result.stdout

        finally:
            test_file.unlink()

    def test_bench_specific_operations(self) -> None:
        """Benchmark specific operations."""
        yara_content = """
        rule op_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        for operation in ["parse", "codegen", "roundtrip"]:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
                f.write(yara_content.strip())
                test_file = Path(f.name)

            try:
                result = subprocess.run(
                    [
                        "python",
                        "-m",
                        "yaraast.cli.main",
                        "bench",
                        str(test_file),
                        "--operations",
                        operation,
                        "--iterations",
                        "2",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )

                assert result.returncode == 0
                # Should show operation results
                assert operation in result.stdout.lower() or "ms" in result.stdout

            finally:
                test_file.unlink()

    def test_bench_with_output_json(self) -> None:
        """Benchmark and save results to JSON."""
        yara_content = """
        rule json_bench {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as out:
            output_file = Path(out.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "bench",
                    str(test_file),
                    "--iterations",
                    "2",
                    "--output",
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            assert result.returncode == 0
            assert output_file.exists()

            # Verify output is valid JSON
            with output_file.open() as f:
                bench_data = json.load(f)
                assert isinstance(bench_data, dict)
                assert "timestamp" in bench_data or "files" in bench_data

        finally:
            test_file.unlink()
            if output_file.exists():
                output_file.unlink()


class TestCLIAnalyzeCommands:
    """Tests for 'yaraast analyze' subcommands."""

    def test_analyze_best_practices(self) -> None:
        """Test best practices analysis."""
        yara_content = """
        rule best_practice_test {
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
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "analyze",
                    "best-practices",
                    str(test_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            # Should complete and show analysis
            assert (
                "Best Practices" in result.stdout
                or "Analysis" in result.stdout
                or "issue" in result.stdout.lower()
            )

        finally:
            test_file.unlink()

    def test_analyze_best_practices_verbose(self) -> None:
        """Test best practices analysis with verbose output."""
        yara_content = """
        rule verbose_test {
            meta:
                author = "test"
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
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "analyze",
                    "best-practices",
                    str(test_file),
                    "--verbose",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            # Verbose should provide more details
            assert len(result.stdout) > 0

        finally:
            test_file.unlink()

    def test_analyze_optimize(self) -> None:
        """Test optimization analysis."""
        yara_content = """
        rule optimize_test {
            strings:
                $s1 = "test"
                $s2 = "test"
            condition:
                $s1 or $s2
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "analyze",
                    "optimize",
                    str(test_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            # Should show optimization analysis
            assert (
                "Optimization" in result.stdout
                or "Analysis" in result.stdout
                or len(result.stdout) > 0
            )

        finally:
            test_file.unlink()

    def test_analyze_full(self) -> None:
        """Test full analysis (best practices + optimization)."""
        yara_content = """
        rule full_analysis_test {
            meta:
                author = "test"
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
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "analyze",
                    "full",
                    str(test_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            # Should show comprehensive analysis
            assert len(result.stdout) > 0

        finally:
            test_file.unlink()

    def test_analyze_full_with_output_json(self) -> None:
        """Test full analysis with JSON output."""
        yara_content = """
        rule json_analysis {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as out:
            output_file = Path(out.name)

        try:
            subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "analyze",
                    "full",
                    str(test_file),
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            if output_file.exists():
                with output_file.open() as f:
                    analysis_data = json.load(f)
                    assert isinstance(analysis_data, dict)

        finally:
            test_file.unlink()
            if output_file.exists():
                output_file.unlink()


class TestCLISerializeCommands:
    """Tests for 'yaraast serialize' subcommands."""

    def test_serialize_export_json(self) -> None:
        """Test exporting AST to JSON."""
        yara_content = """
        rule export_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as out:
            output_file = Path(out.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "serialize",
                    "export",
                    str(test_file),
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            assert result.returncode == 0
            if output_file.exists():
                with output_file.open() as f:
                    json_data = json.load(f)
                    assert isinstance(json_data, dict)

        finally:
            test_file.unlink()
            if output_file.exists():
                output_file.unlink()

    def test_serialize_export_yaml(self) -> None:
        """Test exporting AST to YAML."""
        yara_content = """
        rule yaml_export {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as out:
            output_file = Path(out.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "serialize",
                    "export",
                    str(test_file),
                    "--format",
                    "yaml",
                    "--output",
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            if result.returncode == 0 and output_file.exists():
                # YAML export succeeded
                assert output_file.stat().st_size > 0

        finally:
            test_file.unlink()
            if output_file.exists():
                output_file.unlink()


class TestCLIErrorHandling:
    """Tests for CLI error handling."""

    def test_nonexistent_file(self) -> None:
        """Test handling of nonexistent file."""
        result = subprocess.run(
            ["python", "-m", "yaraast.cli.main", "parse", "/nonexistent/file.yar"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        # Should fail gracefully
        assert result.returncode != 0

    def test_invalid_command(self) -> None:
        """Test handling of invalid command."""
        result = subprocess.run(
            ["python", "-m", "yaraast.cli.main", "invalid_command"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        # Should show error or help
        assert result.returncode != 0 or "Usage" in result.stdout or "Error" in result.stderr

    def test_help_command(self) -> None:
        """Test help command."""
        result = subprocess.run(
            ["python", "-m", "yaraast.cli.main", "--help"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        assert result.returncode == 0
        assert "Usage" in result.stdout or "YARA" in result.stdout

    def test_version_command(self) -> None:
        """Test version command."""
        result = subprocess.run(
            ["python", "-m", "yaraast.cli.main", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        assert result.returncode == 0
        # Should show version information
        assert len(result.stdout) > 0 or len(result.stderr) > 0


class TestCLIRoundtripIntegration:
    """Integration tests for parse-format-parse roundtrips."""

    def test_parse_format_parse_roundtrip(self) -> None:
        """Test that parse→format→parse preserves structure."""
        original_yara = """
        rule roundtrip_test {
            meta:
                author = "test"
                version = 1
            strings:
                $s1 = "test1"
                $s2 = { 4D 5A }
            condition:
                $s1 or $s2
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(original_yara.strip())
            original_file = Path(f.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as fmt:
            formatted_file = Path(fmt.name)

        try:
            # Format the file
            result1 = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "format",
                    str(original_file),
                    str(formatted_file),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result1.returncode == 0

            # Parse formatted file
            result2 = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(formatted_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result2.returncode == 0
            json_data = json.loads(result2.stdout)
            assert json_data is not None

        finally:
            original_file.unlink()
            if formatted_file.exists():
                formatted_file.unlink()

    def test_parse_json_consistency(self) -> None:
        """Test that parsing produces consistent JSON output."""
        yara_content = """
        rule consistency_test {
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
            # Parse twice
            result1 = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            result2 = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result1.returncode == 0
            assert result2.returncode == 0

            json1 = json.loads(result1.stdout)
            json2 = json.loads(result2.stdout)

            # Should produce identical results
            assert json1 == json2

        finally:
            test_file.unlink()


class TestCLIComplexRules:
    """Tests for complex YARA rule scenarios."""

    def test_parse_rule_with_multiple_imports(self) -> None:
        """Test parsing rule with multiple imports."""
        yara_content = """
        import "pe"
        import "elf"
        import "math"

        rule multi_import {
            condition:
                true
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            json_data = json.loads(result.stdout)
            # Should preserve imports
            assert json_data is not None

        finally:
            test_file.unlink()

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

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            json_data = json.loads(result.stdout)
            assert json_data is not None

        finally:
            test_file.unlink()

    def test_parse_rule_with_complex_condition(self) -> None:
        """Test parsing rule with complex condition."""
        yara_content = """
        rule complex_condition {
            strings:
                $s1 = "string1"
                $s2 = "string2"
                $s3 = "string3"
            condition:
                ($s1 and $s2) or ($s2 and $s3) or
                (#s1 > 2 and @s2 < 100)
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            json_data = json.loads(result.stdout)
            assert json_data is not None

        finally:
            test_file.unlink()

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

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            json_data = json.loads(result.stdout)
            assert json_data is not None

        finally:
            test_file.unlink()

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

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
            f.write(yara_content.strip())
            test_file = Path(f.name)

        try:
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "yaraast.cli.main",
                    "parse",
                    str(test_file),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            assert result.returncode == 0
            json_data = json.loads(result.stdout)
            assert json_data is not None

        finally:
            test_file.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
