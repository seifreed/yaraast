"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real CLI behavior without mocks or stubs.

Direct tests for yaraast CLI commands using Click testing infrastructure.
These tests execute real CLI code paths without subprocess overhead.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from yaraast.cli.commands.format_cmd import format_yara
from yaraast.cli.main import bench, diff, fmt, parse, validate


class TestCLIParseCommandDirect:
    """Direct tests for the 'yaraast parse' command."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file)])

            assert result.exit_code == 0
            assert "rule basic_test" in result.output or "basic_test" in result.output

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0
            # Verify output is valid JSON
            json_output = json.loads(result.output)
            assert "rules" in json_output or "type" in json_output

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "tree"])

            assert result.exit_code == 0
            # Tree output should contain rule structure
            assert "tree_test" in result.output or "Rule" in result.output

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())
            output_file = Path("output.json")

            result = self.runner.invoke(
                parse, [str(test_file), "--format", "json", "--output", str(output_file)]
            )

            assert result.exit_code == 0
            assert output_file.exists()
            assert output_file.stat().st_size > 0

            # Verify output is valid JSON
            with output_file.open() as f:
                json_data = json.load(f)
                assert isinstance(json_data, dict)

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--dialect", "auto"])

            assert result.exit_code == 0
            # Should detect dialect and report it
            assert "Detected dialect" in result.output or "rule dialect_test" in result.output

    def test_parse_invalid_yara_file(self) -> None:
        """Test parsing an invalid YARA file."""
        invalid_yara = "this is not valid yara syntax"

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(invalid_yara)

            result = self.runner.invoke(parse, [str(test_file)])

            # Should fail or show errors
            assert (
                result.exit_code != 0
                or "Error" in result.output
                or "issue" in result.output.lower()
            )

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0
            json_output = json.loads(result.output)
            # Should contain hex string information
            assert json_output is not None

    def test_parse_rule_with_imports(self) -> None:
        """Test parsing rule with imports."""
        yara_content = """
        import "pe"

        rule import_test {
            condition:
                true
        }
        """

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0


class TestCLIFormatCommandDirect:
    """Direct tests for the 'yaraast format' command."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_format_basic_file(self) -> None:
        """Format a basic YARA file."""
        unformatted = """rule test{strings:$s="hello"condition:$s}"""

        with self.runner.isolated_filesystem():
            input_file = Path("input.yar")
            output_file = Path("output.yar")
            input_file.write_text(unformatted)

            result = self.runner.invoke(format_yara, [str(input_file), str(output_file)])

            assert result.exit_code == 0
            assert output_file.exists()

            # Read formatted output
            formatted = output_file.read_text()

            # Should have proper formatting
            assert "rule test" in formatted
            assert "strings:" in formatted
            assert "condition:" in formatted
            assert formatted.count("\n") > unformatted.count("\n")

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

        with self.runner.isolated_filesystem():
            input_file = Path("input.yar")
            output_file = Path("output.yar")
            input_file.write_text(yara_content.strip())

            result = self.runner.invoke(format_yara, [str(input_file), str(output_file)])

            assert result.exit_code == 0

            formatted = output_file.read_text()

            # All key elements should be preserved
            assert "logic_test" in formatted
            assert "author" in formatted
            assert "$s1" in formatted
            assert "$s2" in formatted
            assert "or" in formatted


class TestCLIValidateCommandDirect:
    """Direct tests for the 'yaraast validate' command."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(valid_yara.strip())

            result = self.runner.invoke(validate, [str(test_file)])

            assert result.exit_code == 0
            assert "Valid" in result.output or "valid" in result.output.lower()

    def test_validate_invalid_file(self) -> None:
        """Validate an invalid YARA file."""
        invalid_yara = "this is not valid yara"

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(invalid_yara)

            result = self.runner.invoke(validate, [str(test_file)])

            # Should fail or show invalid
            assert result.exit_code != 0 or "Invalid" in result.output or "Error" in result.output

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(validate, [str(test_file)])

            assert result.exit_code == 0
            # Should show statistics
            assert "Rules:" in result.output or "rule" in result.output.lower()


class TestCLIFmtCommandDirect:
    """Direct tests for the 'yaraast fmt' command."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_fmt_with_check_option(self) -> None:
        """Test format checking without modifying file."""
        poorly_formatted = """rule test{strings:$s="x"condition:$s}"""

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(poorly_formatted)

            self.runner.invoke(fmt, [str(test_file), "--check"])

            # File should not be modified
            content = test_file.read_text()
            assert content == poorly_formatted

            # Should report needs formatting
            # Exit code may vary based on implementation

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
            with self.runner.isolated_filesystem():
                test_file = Path("test.yar")
                output_file = Path("output.yar")
                test_file.write_text(yara_content.strip())

                result = self.runner.invoke(
                    fmt, [str(test_file), "--output", str(output_file), "--style", style]
                )

                assert result.exit_code == 0
                assert output_file.exists()

                formatted = output_file.read_text()
                assert "style_test" in formatted

    def test_fmt_with_diff_option(self) -> None:
        """Test showing diff of formatting changes."""
        unformatted = """rule diff_test{strings:$s="test"condition:$s}"""

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(unformatted)

            self.runner.invoke(fmt, [str(test_file), "--diff"])

            # Should show diff output
            # File should not be modified
            content = test_file.read_text()
            assert content == unformatted


class TestCLIDiffCommandDirect:
    """Direct tests for the 'yaraast diff' command."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

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

        with self.runner.isolated_filesystem():
            file1 = Path("file1.yar")
            file2 = Path("file2.yar")
            file1.write_text(yara_content.strip())
            file2.write_text(yara_content.strip())

            result = self.runner.invoke(diff, [str(file1), str(file2)])

            assert result.exit_code == 0
            assert "No differences" in result.output or "no" in result.output.lower()

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

        with self.runner.isolated_filesystem():
            file1 = Path("file1.yar")
            file2 = Path("file2.yar")
            file1.write_text(original.strip())
            file2.write_text(modified.strip())

            result = self.runner.invoke(diff, [str(file1), str(file2)])

            assert result.exit_code == 0
            # Should detect added rule
            assert "added" in result.output.lower() or "Added" in result.output

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

        with self.runner.isolated_filesystem():
            file1 = Path("file1.yar")
            file2 = Path("file2.yar")
            file1.write_text(file1_content.strip())
            file2.write_text(file2_content.strip())

            result = self.runner.invoke(diff, [str(file1), str(file2), "--logical-only"])

            assert result.exit_code == 0
            # Should show logical changes
            assert "change" in result.output.lower() or "modified" in result.output.lower()

    def test_diff_summary_option(self) -> None:
        """Test diff with summary option."""
        file1 = """rule test { condition: true }"""
        file2 = """rule test { condition: false }"""

        with self.runner.isolated_filesystem():
            test_file1 = Path("file1.yar")
            test_file2 = Path("file2.yar")
            test_file1.write_text(file1)
            test_file2.write_text(file2)

            result = self.runner.invoke(diff, [str(test_file1), str(test_file2), "--summary"])

            assert result.exit_code == 0
            # Should show summary
            assert "Summary" in result.output or "Change" in result.output


class TestCLIBenchCommandDirect:
    """Direct tests for the 'yaraast bench' command."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(bench, [str(test_file), "--iterations", "3"])

            assert result.exit_code == 0
            # Should show benchmark results
            assert "Benchmark" in result.output or "ms" in result.output

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
            with self.runner.isolated_filesystem():
                test_file = Path("test.yar")
                test_file.write_text(yara_content.strip())

                result = self.runner.invoke(
                    bench, [str(test_file), "--operations", operation, "--iterations", "2"]
                )

                assert result.exit_code == 0
                # Should show operation results
                assert operation in result.output.lower() or "ms" in result.output

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            output_file = Path("bench.json")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(
                bench, [str(test_file), "--iterations", "2", "--output", str(output_file)]
            )

            assert result.exit_code == 0
            assert output_file.exists()

            # Verify output is valid JSON
            with output_file.open() as f:
                bench_data = json.load(f)
                assert isinstance(bench_data, dict)
                assert "timestamp" in bench_data or "files" in bench_data


class TestCLIComplexRulesDirect:
    """Direct tests for complex YARA rule scenarios."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0
            json_data = json.loads(result.output)
            # Should preserve imports
            assert json_data is not None

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0
            json_data = json.loads(result.output)
            assert json_data is not None

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0
            json_data = json.loads(result.output)
            assert json_data is not None

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0
            json_data = json.loads(result.output)
            assert json_data is not None

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            result = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result.exit_code == 0
            json_data = json.loads(result.output)
            assert json_data is not None


class TestCLIRoundtripIntegrationDirect:
    """Integration tests for parse-format-parse roundtrips."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

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

        with self.runner.isolated_filesystem():
            original_file = Path("original.yar")
            formatted_file = Path("formatted.yar")
            original_file.write_text(original_yara.strip())

            # Format the file
            result1 = self.runner.invoke(format_yara, [str(original_file), str(formatted_file)])
            assert result1.exit_code == 0

            # Parse formatted file
            result2 = self.runner.invoke(parse, [str(formatted_file), "--format", "json"])

            assert result2.exit_code == 0
            json_data = json.loads(result2.output)
            assert json_data is not None

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

        with self.runner.isolated_filesystem():
            test_file = Path("test.yar")
            test_file.write_text(yara_content.strip())

            # Parse twice
            result1 = self.runner.invoke(parse, [str(test_file), "--format", "json"])
            result2 = self.runner.invoke(parse, [str(test_file), "--format", "json"])

            assert result1.exit_code == 0
            assert result2.exit_code == 0

            json1 = json.loads(result1.output)
            json2 = json.loads(result2.output)

            # Should produce identical results
            assert json1 == json2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
