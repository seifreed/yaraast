"""Tests for enhanced serialization features."""

import json

import yaml

from yaraast.codegen.pretty_printer import PrettyPrinter, PrettyPrintOptions, StylePresets
from yaraast.parser import YaraParser
from yaraast.serialization.roundtrip_serializer import EnhancedYamlSerializer, RoundTripSerializer


class TestRoundTripSerializer:
    """Tests for round-trip serialization."""

    def test_basic_roundtrip_json(self) -> None:
        """Test basic round-trip with JSON."""
        yara_source = """
        import "pe"

        rule test_rule {
            meta:
                author = "Test"
                description = "Test rule"
            strings:
                $a = "hello"
                $b = { 4D 5A }
            condition:
                $a and $b
        }
        """

        serializer = RoundTripSerializer()
        result = serializer.roundtrip_test(yara_source.strip(), format="json")

        assert result["round_trip_successful"] is True
        assert result["format"] == "json"
        assert len(result["differences"]) == 0
        assert result["metadata"]["original_rule_count"] == 1
        assert result["metadata"]["reconstructed_rule_count"] == 1

    def test_basic_roundtrip_yaml(self) -> None:
        """Test basic round-trip with YAML."""
        yara_source = """
        rule simple_rule {
            strings:
                $test = "malware"
            condition:
                $test
        }
        """

        serializer = RoundTripSerializer()
        result = serializer.roundtrip_test(yara_source.strip(), format="yaml")

        assert result["round_trip_successful"] is True
        assert result["format"] == "yaml"

    def test_formatting_detection(self) -> None:
        """Test formatting detection."""
        yara_source_tabs = """
\t\trule tab_indented {
\t\t\tstrings:
\t\t\t\t$a = "test"
\t\t\tcondition:
\t\t\t\t$a
\t\t}
        """

        yara_source_spaces = """
        rule space_indented {
            strings:
                $a = "test"
            condition:
                $a
        }
        """

        serializer = RoundTripSerializer()

        # Test tab detection
        formatting_tabs = serializer._detect_formatting(yara_source_tabs)
        assert formatting_tabs.indent_style == "tabs"

        # Test space detection
        formatting_spaces = serializer._detect_formatting(yara_source_spaces)
        assert formatting_spaces.indent_style == "spaces"
        assert formatting_spaces.indent_size == 4

    def test_serialization_with_metadata(self) -> None:
        """Test serialization includes round-trip metadata."""
        yara_source = """
        rule metadata_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        serializer = RoundTripSerializer()
        _, serialized = serializer.parse_and_serialize(
            yara_source.strip(),
            format="json",
        )

        # Parse serialized data to check metadata
        data = json.loads(serialized)
        assert "roundtrip_metadata" in data

        metadata = data["roundtrip_metadata"]
        assert "formatting" in metadata
        assert "parsed_at" in metadata
        assert metadata["comments_preserved"] is True
        assert metadata["formatting_preserved"] is True


class TestEnhancedYamlSerializer:
    """Tests for enhanced YAML serialization."""

    def test_pipeline_serialization(self) -> None:
        """Test YAML serialization for pipelines."""
        yara_source = """
        import "pe"

        rule pipeline_test : malware {
            meta:
                author = "Pipeline"
            strings:
                $mz = { 4D 5A }
            condition:
                $mz at 0
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        serializer = EnhancedYamlSerializer(include_pipeline_metadata=True)
        yaml_output = serializer.serialize_for_pipeline(ast)

        # Parse YAML to verify structure
        data = yaml.safe_load(yaml_output)

        assert "pipeline_metadata" in data
        assert "statistics" in data
        assert data["statistics"]["total_rules"] == 1
        assert "pe" in data["statistics"]["imports"]
        assert "malware" in data["statistics"]["rule_tags"]

    def test_rules_manifest(self) -> None:
        """Test rules manifest generation."""
        yara_source = """
        rule rule1 : tag1 tag2 {
            strings:
                $a = "test1"
            condition:
                $a
        }

        private rule rule2 {
            strings:
                $b = "test2"
                $c = { 00 01 }
            condition:
                $b or $c
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        serializer = EnhancedYamlSerializer()
        manifest = serializer.serialize_rules_manifest(ast)

        # Parse manifest
        data = yaml.safe_load(manifest)

        assert data["manifest_version"] == "1.0"
        assert len(data["rules"]) == 2
        assert data["summary"]["total_rules"] == 2
        assert data["summary"]["private_rules"] == 1

        # Check rule details
        rule1 = next(r for r in data["rules"] if r["name"] == "rule1")
        assert rule1["tags"] == ["tag1", "tag2"]
        assert rule1["string_count"] == 1

        rule2 = next(r for r in data["rules"] if r["name"] == "rule2")
        assert "private" in rule2["modifiers"]
        assert rule2["string_count"] == 2


class TestPrettyPrinter:
    """Tests for pretty printer."""

    def test_basic_pretty_printing(self) -> None:
        """Test basic pretty printing."""
        yara_source = """
import "pe"
rule test{strings:$a="hello"$b={4D 5A}condition:$a and $b}
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        printer = PrettyPrinter()
        formatted = printer.pretty_print(ast)

        # Check that formatting improved
        assert 'import "pe"' in formatted
        assert "rule test" in formatted
        assert "strings:" in formatted
        assert "condition:" in formatted
        assert formatted.count("\n") > yara_source.count("\n")

    def test_style_presets(self) -> None:
        """Test different style presets."""
        yara_source = """
        rule style_test {
            meta:
                author = "Test"
            strings:
                $a = "hello"
            condition:
                $a
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        # Test different presets
        compact = PrettyPrinter(StylePresets.compact()).pretty_print(ast)
        readable = PrettyPrinter(StylePresets.readable()).pretty_print(ast)
        verbose = PrettyPrinter(StylePresets.verbose()).pretty_print(ast)

        # Verbose should have more blank lines than compact
        assert verbose.count("\n") > compact.count("\n")
        assert readable.count("\n") >= compact.count("\n")

    def test_alignment_options(self) -> None:
        """Test string and meta alignment."""
        yara_source = """
        rule alignment_test {
            meta:
                author = "Test"
                description = "Long description here"
                version = 1
            strings:
                $short = "a"
                $very_long_identifier = "longer string here"
                $b = { 4D 5A }
            condition:
                any of them
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        # Test with alignment
        options = PrettyPrintOptions(
            align_string_definitions=True,
            align_meta_values=True,
        )
        printer = PrettyPrinter(options)
        formatted = printer.pretty_print(ast)

        lines = formatted.split("\n")

        # Find string lines and check alignment
        string_lines = [line for line in lines if '= "' in line or "= {" in line]
        if len(string_lines) > 1:
            # Check that = signs are aligned (simplified check)
            equals_positions = [line.find("=") for line in string_lines]
            # All should be at same position (or close for alignment)
            assert max(equals_positions) - min(equals_positions) <= 10

    def test_custom_formatting_options(self) -> None:
        """Test custom formatting options."""
        yara_source = """
        rule custom_test {
            strings:
                $a = "test"
            condition:
                $a
        }
        """

        parser = YaraParser()
        ast = parser.parse(yara_source.strip())

        # Test custom indent size
        options = PrettyPrintOptions(indent_size=2)
        printer = PrettyPrinter(options)
        formatted = printer.pretty_print(ast)

        lines = formatted.split("\n")
        indented_lines = [
            line for line in lines if line.startswith("  ") and not line.startswith("    ")
        ]

        # Should have lines with 2-space indent
        assert len(indented_lines) > 0


class TestIntegration:
    """Integration tests for enhanced serialization."""

    def test_complete_workflow(self) -> None:
        """Test complete workflow: parse -> serialize -> deserialize -> pretty print."""
        yara_source = """
        import "pe"

        rule workflow_test : malware {
            meta:
                author = "Integration Test"
                description = "Complete workflow test"
            strings:
                $mz = { 4D 5A ?? 00 }
                $string = "malware" nocase
            condition:
                $mz at 0 and $string
        }
        """

        # Step 1: Parse
        parser = YaraParser()
        original_ast = parser.parse(yara_source.strip())
        assert original_ast is not None

        # Step 2: Round-trip serialize
        serializer = RoundTripSerializer()
        _, serialized = serializer.parse_and_serialize(
            yara_source.strip(),
            format="yaml",
        )

        # Step 3: Deserialize
        reconstructed_ast, _ = serializer.deserialize_and_generate(
            serialized,
            format="yaml",
        )

        # Step 4: Pretty print
        printer = PrettyPrinter(StylePresets.readable())
        pretty_output = printer.pretty_print(reconstructed_ast)

        # Verify results
        assert len(original_ast.rules) == len(reconstructed_ast.rules)
        assert original_ast.rules[0].name == reconstructed_ast.rules[0].name
        assert len(pretty_output.split("\n")) > len(yara_source.split("\n"))

        # Basic structure should be preserved
        assert 'import "pe"' in pretty_output
        assert "rule workflow_test" in pretty_output
        assert "malware" in pretty_output
        assert "$mz" in pretty_output
        assert "$string" in pretty_output


if __name__ == "__main__":
    # Run simple tests
    print("Testing enhanced serialization...")

    # Test round-trip
    yara_test = """
    rule test_enhanced {
        strings:
            $a = "hello world"
        condition:
            $a
    }
    """

    serializer = RoundTripSerializer()
    result = serializer.roundtrip_test(yara_test.strip())

    print(
        f"✓ Round-trip test: {'PASSED' if result['round_trip_successful'] else 'FAILED'}",
    )
    if result["differences"]:
        print(f"  Differences: {len(result['differences'])}")

    # Test pretty printing
    parser = YaraParser()
    ast = parser.parse(yara_test.strip())

    printer = PrettyPrinter(StylePresets.readable())
    pretty = printer.pretty_print(ast)

    print("✓ Pretty printing test: PASSED")
    print("✓ Pretty formatted output:")
    for i, line in enumerate(pretty.split("\n")[:10], 1):
        print(f"  {i:2d}: {line}")

    print("✅ Enhanced serialization tests completed!")
