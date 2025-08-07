"""Test advanced serialization features."""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from yaraast.parser import Parser
from yaraast.serialization import (
    AstDiff,
    DiffType,
    JsonSerializer,
    ProtobufSerializer,
    YamlSerializer,
)


class TestJsonSerializer:
    """Test JSON serialization."""

    def test_serialize_simple_rule(self) -> None:
        """Test JSON serialization of simple rule."""
        rule_text = """
        rule test_rule {
            strings:
                $a = "test"
            condition:
                $a
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        serializer = JsonSerializer()
        json_str = serializer.serialize(ast)

        # Should be valid JSON
        data = json.loads(json_str)
        assert "metadata" in data
        assert "ast" in data
        assert data["metadata"]["format"] == "yaraast-json"
        assert data["ast"]["type"] == "YaraFile"
        assert len(data["ast"]["rules"]) == 1
        assert data["ast"]["rules"][0]["name"] == "test_rule"

    def test_serialize_with_metadata(self) -> None:
        """Test serialization with metadata."""
        rule_text = "rule test { condition: true }"

        parser = Parser()
        ast = parser.parse(rule_text)

        serializer = JsonSerializer(include_metadata=True)
        json_str = serializer.serialize(ast)

        data = json.loads(json_str)
        assert "metadata" in data
        assert data["metadata"]["rules_count"] == 1
        assert data["metadata"]["imports_count"] == 0

    def test_serialize_without_metadata(self) -> None:
        """Test serialization without metadata."""
        rule_text = "rule test { condition: true }"

        parser = Parser()
        ast = parser.parse(rule_text)

        serializer = JsonSerializer(include_metadata=False)
        json_str = serializer.serialize(ast)

        data = json.loads(json_str)
        assert "metadata" not in data
        assert "ast" in data

    def test_serialize_to_file(self) -> None:
        """Test serialization to file."""
        rule_text = "rule test { condition: true }"

        parser = Parser()
        ast = parser.parse(rule_text)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            serializer = JsonSerializer()
            serializer.serialize(ast, temp_path)

            # Verify file was created and contains valid JSON
            with Path(temp_path).open() as f:
                data = json.load(f)

            assert data["ast"]["type"] == "YaraFile"
            assert len(data["ast"]["rules"]) == 1
        finally:
            Path(temp_path).unlink()


class TestYamlSerializer:
    """Test YAML serialization."""

    def test_serialize_simple_rule(self) -> None:
        """Test YAML serialization of simple rule."""
        rule_text = """
        rule test_rule {
            strings:
                $a = "test"
            condition:
                $a
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        serializer = YamlSerializer()
        yaml_str = serializer.serialize(ast)

        # Should be valid YAML
        data = yaml.safe_load(yaml_str)
        assert "metadata" in data
        assert "ast" in data
        assert data["metadata"]["format"] == "yaraast-yaml"
        assert data["ast"]["type"] == "YaraFile"
        assert len(data["ast"]["rules"]) == 1
        assert data["ast"]["rules"][0]["name"] == "test_rule"

    def test_serialize_minimal(self) -> None:
        """Test minimal YAML serialization."""
        rule_text = "rule test { condition: true }"

        parser = Parser()
        ast = parser.parse(rule_text)

        serializer = YamlSerializer()
        yaml_str = serializer.serialize_minimal(ast)

        data = yaml.safe_load(yaml_str)
        assert "type" in data  # Direct AST, no wrapper
        assert data["type"] == "YaraFile"
        assert len(data["rules"]) == 1

    def test_serialize_rules_only(self) -> None:
        """Test rules-only YAML serialization."""
        rule_text = """
        rule rule1 { condition: true }
        rule rule2 { condition: false }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        serializer = YamlSerializer()
        yaml_str = serializer.serialize_rules_only(ast)

        data = yaml.safe_load(yaml_str)
        assert "rules" in data
        assert "rule_count" in data
        assert data["rule_count"] == 2
        assert len(data["rules"]) == 2
        assert data["rules"][0]["name"] in ["rule1", "rule2"]


class TestProtobufSerializer:
    """Test Protobuf serialization."""

    def test_protobuf_available(self) -> None:
        """Test if protobuf serialization is available."""
        try:
            serializer = ProtobufSerializer()
            # If we get here, protobuf is available
            assert serializer is not None
        except ImportError:
            # Skip protobuf tests if not available
            pytest.skip("Protobuf schema not compiled")

    def test_serialize_simple_rule(self) -> None:
        """Test Protobuf serialization of simple rule."""
        try:
            rule_text = "rule test { condition: true }"

            parser = Parser()
            ast = parser.parse(rule_text)

            serializer = ProtobufSerializer()
            binary_data = serializer.serialize(ast)

            # Should be bytes
            assert isinstance(binary_data, bytes)
            assert len(binary_data) > 0
        except ImportError:
            pytest.skip("Protobuf schema not compiled")

    def test_serialize_text_format(self) -> None:
        """Test Protobuf text serialization."""
        try:
            rule_text = "rule test { condition: true }"

            parser = Parser()
            ast = parser.parse(rule_text)

            serializer = ProtobufSerializer()
            text_data = serializer.serialize_text(ast)

            # Should be string representation
            assert isinstance(text_data, str)
            assert "test" in text_data  # Rule name should appear
        except ImportError:
            pytest.skip("Protobuf schema not compiled")

    def test_serialization_stats(self) -> None:
        """Test serialization statistics."""
        try:
            rule_text = """
            rule test1 { condition: true }
            rule test2 { condition: false }
            """

            parser = Parser()
            ast = parser.parse(rule_text)

            serializer = ProtobufSerializer()
            stats = serializer.get_serialization_stats(ast)

            assert "binary_size_bytes" in stats
            assert "text_size_bytes" in stats
            assert "compression_ratio" in stats
            assert stats["rules_count"] == 2
            assert stats["imports_count"] == 0
            assert stats["binary_size_bytes"] > 0
        except ImportError:
            pytest.skip("Protobuf schema not compiled")


class TestAstDiff:
    """Test AST diff functionality."""

    def test_identical_asts(self) -> None:
        """Test diff of identical ASTs."""
        rule_text = "rule test { condition: true }"

        parser = Parser()
        ast1 = parser.parse(rule_text)
        ast2 = parser.parse(rule_text)

        differ = AstDiff()
        result = differ.compare(ast1, ast2)

        assert not result.has_changes
        assert len(result.differences) == 0
        assert result.old_ast_hash == result.new_ast_hash

    def test_rule_added(self) -> None:
        """Test detection of added rule."""
        old_text = "rule test1 { condition: true }"
        new_text = """
        rule test1 { condition: true }
        rule test2 { condition: false }
        """

        parser = Parser()
        old_ast = parser.parse(old_text)
        new_ast = parser.parse(new_text)

        differ = AstDiff()
        result = differ.compare(old_ast, new_ast)

        assert result.has_changes
        assert len(result.differences) > 0

        added_rules = result.get_changes_by_type(DiffType.ADDED)
        assert len(added_rules) == 1
        assert added_rules[0].path == "/rules/test2"
        assert added_rules[0].new_value == "test2"

    def test_rule_removed(self) -> None:
        """Test detection of removed rule."""
        old_text = """
        rule test1 { condition: true }
        rule test2 { condition: false }
        """
        new_text = "rule test1 { condition: true }"

        parser = Parser()
        old_ast = parser.parse(old_text)
        new_ast = parser.parse(new_text)

        differ = AstDiff()
        result = differ.compare(old_ast, new_ast)

        assert result.has_changes

        removed_rules = result.get_changes_by_type(DiffType.REMOVED)
        assert len(removed_rules) == 1
        assert removed_rules[0].path == "/rules/test2"
        assert removed_rules[0].old_value == "test2"

    def test_rule_modified(self) -> None:
        """Test detection of modified rule."""
        old_text = """
        rule test {
            strings:
                $a = "old"
            condition:
                $a
        }
        """
        new_text = """
        rule test {
            strings:
                $a = "new"
            condition:
                $a
        }
        """

        parser = Parser()
        old_ast = parser.parse(old_text)
        new_ast = parser.parse(new_text)

        differ = AstDiff()
        result = differ.compare(old_ast, new_ast)

        assert result.has_changes

        # Should detect string modification
        string_changes = [d for d in result.differences if d.path.startswith("/rules/test/strings")]
        assert len(string_changes) > 0

    def test_import_changes(self) -> None:
        """Test detection of import changes."""
        old_text = 'import "pe" rule test { condition: true }'
        new_text = """
        import "pe"
        import "elf"
        rule test { condition: true }
        """

        parser = Parser()
        old_ast = parser.parse(old_text)
        new_ast = parser.parse(new_text)

        differ = AstDiff()
        result = differ.compare(old_ast, new_ast)

        assert result.has_changes

        added_imports = [
            d
            for d in result.differences
            if d.path.startswith("/imports") and d.diff_type == DiffType.ADDED
        ]
        assert len(added_imports) == 1
        assert added_imports[0].new_value == "elf"

    def test_change_summary(self) -> None:
        """Test change summary generation."""
        old_text = "rule test1 { condition: true }"
        new_text = """
        rule test1 { condition: false }
        rule test2 { condition: true }
        """

        parser = Parser()
        old_ast = parser.parse(old_text)
        new_ast = parser.parse(new_text)

        differ = AstDiff()
        result = differ.compare(old_ast, new_ast)

        summary = result.change_summary
        assert isinstance(summary, dict)
        assert "added" in summary
        assert "removed" in summary
        assert "modified" in summary

    def test_create_patch(self) -> None:
        """Test patch creation."""
        old_text = "rule test1 { condition: true }"
        new_text = "rule test2 { condition: false }"

        parser = Parser()
        old_ast = parser.parse(old_text)
        new_ast = parser.parse(new_text)

        differ = AstDiff()
        result = differ.compare(old_ast, new_ast)

        patch = differ.create_patch(result)

        assert "patch_format" in patch
        assert patch["patch_format"] == "yaraast-diff-v1"
        assert "old_hash" in patch
        assert "new_hash" in patch
        assert "changes" in patch
        assert "timestamp" in patch

    def test_diff_to_dict(self) -> None:
        """Test diff result serialization."""
        old_text = "rule test1 { condition: true }"
        new_text = "rule test2 { condition: false }"

        parser = Parser()
        old_ast = parser.parse(old_text)
        new_ast = parser.parse(new_text)

        differ = AstDiff()
        result = differ.compare(old_ast, new_ast)

        data = result.to_dict()

        assert "old_ast_hash" in data
        assert "new_ast_hash" in data
        assert "has_changes" in data
        assert "change_summary" in data
        assert "differences" in data
        assert "statistics" in data

        # Should be JSON serializable
        json_str = json.dumps(data)
        assert len(json_str) > 0


class TestSerializationRoundTrip:
    """Test serialization round-trip scenarios."""

    def test_json_roundtrip_structure(self) -> None:
        """Test JSON serialization preserves structure."""
        rule_text = """
        import "pe"

        rule complex_rule : tag1 tag2 {
            meta:
                author = "test"
                version = 1
            strings:
                $hex = { 48 65 6c 6c 6f }
                $str = "test" wide nocase
                $regex = /pattern/i
            condition:
                $hex and $str and $regex
        }
        """

        parser = Parser()
        original_ast = parser.parse(rule_text)

        # Serialize to JSON
        serializer = JsonSerializer()
        json_str = serializer.serialize(original_ast)

        # Verify JSON structure
        data = json.loads(json_str)
        rule_data = data["ast"]["rules"][0]

        assert rule_data["name"] == "complex_rule"
        assert len(rule_data["tags"]) == 2
        assert len(rule_data["meta"]) == 2
        assert len(rule_data["strings"]) == 3
        assert rule_data["condition"] is not None

        # Check string types
        string_types = [s["type"] for s in rule_data["strings"]]
        assert "HexString" in string_types
        assert "PlainString" in string_types
        assert "RegexString" in string_types

    def test_yaml_preserves_readability(self) -> None:
        """Test YAML serialization preserves human readability."""
        rule_text = """
        rule readable_rule {
            meta:
                description = "Human readable"
            strings:
                $a = "test"
            condition:
                $a
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        serializer = YamlSerializer()
        yaml_str = serializer.serialize(ast)

        # YAML should be human readable
        assert "readable_rule" in yaml_str
        assert "Human readable" in yaml_str
        assert "test" in yaml_str

        # Should not be minified/compact
        lines = yaml_str.split("\n")
        assert len(lines) > 10  # Should be well formatted
