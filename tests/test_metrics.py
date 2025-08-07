"""Tests for metrics and visualization functionality."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from yaraast.metrics import (
    ComplexityAnalyzer,
    ComplexityMetrics,
    DependencyGraphGenerator,
    HtmlTreeGenerator,
    StringDiagramGenerator,
)
from yaraast.parser import Parser


@pytest.fixture
def sample_yara_content() -> str:
    """Sample YARA content for testing."""
    return """
import "pe"
import "math"

rule TestRule : malware family {
    meta:
        author = "Test Author"
        description = "Test rule"
        version = "1.0"

    strings:
        $str1 = "Hello World" ascii wide
        $str2 = "Test String"
        $hex1 = { 48 65 6C 6C 6F ?? ?? 57 6F 72 6C 64 }
        $hex2 = { 90 90 [4-6] (AA | BB | CC) 90 90 }
        $regex1 = /test[0-9]+/i

    condition:
        pe.is_pe and (
            ($str1 or $str2) and
            for any of ($hex*) : ($ at pe.entry_point) and
            math.entropy(0, 1024) > 7.0
        )
}

private rule PrivateRule {
    strings:
        $a = "private test"

    condition:
        $a
}

global rule GlobalRule {
    condition:
        true
}
"""


@pytest.fixture
def parsed_ast(sample_yara_content):
    """Parse sample YARA content into AST."""
    parser = Parser()
    return parser.parse(sample_yara_content)


class TestComplexityAnalyzer:
    """Test complexity analysis functionality."""

    def test_basic_analysis(self, parsed_ast) -> None:
        """Test basic complexity analysis."""
        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(parsed_ast)

        assert isinstance(metrics, ComplexityMetrics)
        assert metrics.total_rules == 3
        assert metrics.total_imports == 2
        assert metrics.total_includes == 0
        assert metrics.private_rules == 1
        assert metrics.global_rules == 1
        assert metrics.rules_with_strings == 2
        assert metrics.rules_with_meta == 1
        assert metrics.rules_with_tags == 1

    def test_string_analysis(self, parsed_ast) -> None:
        """Test string complexity analysis."""
        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(parsed_ast)

        assert metrics.total_strings == 5
        assert metrics.plain_strings == 2
        assert metrics.hex_strings == 2
        assert metrics.regex_strings == 1
        assert metrics.strings_with_modifiers > 0

        # Check hex pattern analysis
        assert metrics.hex_wildcards > 0
        assert metrics.hex_alternatives > 0

    def test_condition_complexity(self, parsed_ast) -> None:
        """Test condition complexity analysis."""
        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(parsed_ast)

        assert metrics.max_condition_depth > 0
        assert metrics.total_binary_ops > 0
        assert metrics.for_expressions > 0
        assert len(metrics.cyclomatic_complexity) == 3  # One per rule

    def test_quality_scoring(self, parsed_ast) -> None:
        """Test quality scoring system."""
        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(parsed_ast)

        quality_score = metrics.get_quality_score()
        assert 0 <= quality_score <= 100

        grade = metrics.get_complexity_grade()
        assert grade in ["A", "B", "C", "D", "F"]

    def test_metrics_serialization(self, parsed_ast) -> None:
        """Test metrics to dictionary conversion."""
        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(parsed_ast)

        metrics_dict = metrics.to_dict()
        assert isinstance(metrics_dict, dict)
        assert "file_metrics" in metrics_dict
        assert "rule_metrics" in metrics_dict
        assert "string_metrics" in metrics_dict
        assert "condition_metrics" in metrics_dict
        assert "pattern_metrics" in metrics_dict
        assert "quality_metrics" in metrics_dict
        assert "dependencies" in metrics_dict

    def test_empty_file(self) -> None:
        """Test analysis of empty YARA file."""
        parser = Parser()
        ast = parser.parse("")

        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(ast)

        assert metrics.total_rules == 0
        assert metrics.total_strings == 0
        assert metrics.max_condition_depth == 0


class TestDependencyGraphGenerator:
    """Test dependency graph generation."""

    def test_basic_graph_generation(self, parsed_ast) -> None:
        """Test basic dependency graph generation."""
        generator = DependencyGraphGenerator()

        # Test that it returns GraphViz source
        graph_source = generator.generate_graph(parsed_ast)
        assert isinstance(graph_source, str)
        assert "digraph" in graph_source.lower()

    def test_rule_graph(self, parsed_ast) -> None:
        """Test rule-only dependency graph."""
        generator = DependencyGraphGenerator()

        graph_source = generator.generate_rule_graph(parsed_ast)
        assert isinstance(graph_source, str)
        assert "TestRule" in graph_source
        assert "PrivateRule" in graph_source
        assert "GlobalRule" in graph_source

    def test_module_graph(self, parsed_ast) -> None:
        """Test module dependency graph."""
        generator = DependencyGraphGenerator()

        graph_source = generator.generate_module_graph(parsed_ast)
        assert isinstance(graph_source, str)
        assert "pe" in graph_source
        assert "math" in graph_source

    def test_complexity_graph(self, parsed_ast) -> None:
        """Test complexity visualization graph."""
        generator = DependencyGraphGenerator()

        # Create mock complexity metrics
        complexity_metrics = {"TestRule": 8, "PrivateRule": 2, "GlobalRule": 1}

        graph_source = generator.generate_complexity_graph(
            parsed_ast,
            complexity_metrics,
        )
        assert isinstance(graph_source, str)
        assert "Complexity: 8" in graph_source
        assert "Complexity: 2" in graph_source
        assert "Complexity: 1" in graph_source

    def test_file_output(self, parsed_ast) -> None:
        """Test writing graph to file."""
        generator = DependencyGraphGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_graph"

            # Mock graphviz render to avoid requiring GraphViz installation
            with patch("graphviz.Digraph.render") as mock_render:
                mock_render.return_value = str(output_path) + ".svg"

                result_path = generator.generate_graph(
                    parsed_ast,
                    str(output_path),
                    "svg",
                )
                assert result_path.endswith(".svg")
                mock_render.assert_called_once()

    def test_dependency_stats(self, parsed_ast) -> None:
        """Test dependency statistics collection."""
        generator = DependencyGraphGenerator()
        generator.generate_graph(parsed_ast)  # Populate internal state

        stats = generator.get_dependency_stats()
        assert isinstance(stats, dict)
        assert "total_rules" in stats
        assert "total_imports" in stats
        assert "rules_with_strings" in stats
        assert stats["total_rules"] == 3
        assert stats["total_imports"] == 2


class TestHtmlTreeGenerator:
    """Test HTML tree visualization."""

    def test_basic_html_generation(self, parsed_ast) -> None:
        """Test basic HTML tree generation."""
        generator = HtmlTreeGenerator()

        html_content = generator.generate_html(parsed_ast)
        assert isinstance(html_content, str)
        assert "<!DOCTYPE html>" in html_content
        assert "YARA AST Visualization" in html_content
        assert "TestRule" in html_content

    def test_interactive_html(self, parsed_ast) -> None:
        """Test interactive HTML generation with search."""
        generator = HtmlTreeGenerator()

        html_content = generator.generate_interactive_html(
            parsed_ast,
            title="Test Interactive",
        )
        assert isinstance(html_content, str)
        assert "Test Interactive" in html_content
        assert "searchNodes" in html_content  # JavaScript search function
        assert "filterNodes" in html_content  # JavaScript filter function

    def test_html_file_output(self, parsed_ast) -> None:
        """Test writing HTML to file."""
        generator = HtmlTreeGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_tree.html"

            generator.generate_html(parsed_ast, str(output_path))

            assert output_path.exists()
            content = output_path.read_text()
            assert "TestRule" in content
            assert "<!DOCTYPE html>" in content

    def test_metadata_inclusion(self, parsed_ast) -> None:
        """Test metadata inclusion control."""
        # With metadata
        generator_with_meta = HtmlTreeGenerator(include_metadata=True)
        html_with_meta = generator_with_meta.generate_html(parsed_ast)

        # Without metadata
        generator_no_meta = HtmlTreeGenerator(include_metadata=False)
        html_no_meta = generator_no_meta.generate_html(parsed_ast)

        # Both should be valid HTML but different
        assert "<!DOCTYPE html>" in html_with_meta
        assert "<!DOCTYPE html>" in html_no_meta
        assert html_with_meta != html_no_meta

    def test_custom_title(self, parsed_ast) -> None:
        """Test custom page title."""
        generator = HtmlTreeGenerator()
        custom_title = "My Custom YARA Analysis"

        html_content = generator.generate_html(parsed_ast, title=custom_title)
        assert custom_title in html_content
        assert f"<title>{custom_title}</title>" in html_content


class TestStringDiagramGenerator:
    """Test string pattern diagram generation."""

    def test_pattern_flow_diagram(self, parsed_ast) -> None:
        """Test pattern flow diagram generation."""
        generator = StringDiagramGenerator()

        diagram_source = generator.generate_pattern_flow_diagram(parsed_ast)
        assert isinstance(diagram_source, str)
        assert "digraph" in diagram_source.lower()
        assert "Plain String Patterns" in diagram_source
        assert "Hex Patterns" in diagram_source
        assert "Regex Patterns" in diagram_source

    def test_pattern_complexity_diagram(self, parsed_ast) -> None:
        """Test pattern complexity visualization."""
        generator = StringDiagramGenerator()

        diagram_source = generator.generate_pattern_complexity_diagram(parsed_ast)
        assert isinstance(diagram_source, str)
        assert "Complexity" in diagram_source
        assert "neato" in diagram_source  # Should use neato engine

    def test_pattern_similarity_diagram(self, parsed_ast) -> None:
        """Test pattern similarity clustering."""
        generator = StringDiagramGenerator()

        diagram_source = generator.generate_pattern_similarity_diagram(parsed_ast)
        assert isinstance(diagram_source, str)
        assert "fdp" in diagram_source  # Should use fdp engine

    def test_hex_pattern_diagram(self, parsed_ast) -> None:
        """Test hex pattern analysis diagram."""
        generator = StringDiagramGenerator()

        diagram_source = generator.generate_hex_pattern_diagram(parsed_ast)
        assert isinstance(diagram_source, str)
        # Should contain analysis of hex patterns
        assert "$hex1" in diagram_source or "$hex2" in diagram_source

    def test_pattern_statistics(self, parsed_ast) -> None:
        """Test pattern statistics collection."""
        generator = StringDiagramGenerator()

        # Generate any diagram to populate internal state
        generator.generate_pattern_flow_diagram(parsed_ast)

        stats = generator.get_pattern_statistics()
        assert isinstance(stats, dict)
        assert "total_patterns" in stats
        assert "by_type" in stats
        assert "complexity_distribution" in stats
        assert stats["total_patterns"] == 5
        assert stats["by_type"]["plain"] == 2
        assert stats["by_type"]["hex"] == 2
        assert stats["by_type"]["regex"] == 1

    def test_file_output(self, parsed_ast) -> None:
        """Test writing diagram to file."""
        generator = StringDiagramGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_patterns"

            # Mock graphviz render
            with patch("graphviz.Digraph.render") as mock_render:
                mock_render.return_value = str(output_path) + ".svg"

                result_path = generator.generate_pattern_flow_diagram(
                    parsed_ast,
                    str(output_path),
                    "svg",
                )
                assert result_path.endswith(".svg")
                mock_render.assert_called_once()

    def test_empty_patterns(self) -> None:
        """Test handling of files with no string patterns."""
        parser = Parser()
        ast = parser.parse(
            """
        rule EmptyRule {
            condition: true
        }
        """,
        )

        generator = StringDiagramGenerator()

        # Should handle gracefully
        diagram_source = generator.generate_pattern_flow_diagram(ast)
        assert isinstance(diagram_source, str)

        stats = generator.get_pattern_statistics()
        assert stats["total_patterns"] == 0


class TestMetricsIntegration:
    """Test integration between different metrics components."""

    def test_complexity_with_dependency_graph(self, parsed_ast) -> None:
        """Test using complexity metrics with dependency graph."""
        # Get complexity metrics
        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(parsed_ast)

        # Use with dependency graph
        generator = DependencyGraphGenerator()
        graph_source = generator.generate_complexity_graph(
            parsed_ast,
            metrics.cyclomatic_complexity,
        )

        assert isinstance(graph_source, str)
        assert "Complexity" in graph_source

    def test_all_metrics_on_same_ast(self, parsed_ast) -> None:
        """Test that all metrics work on the same AST."""
        # Complexity analysis
        complexity_analyzer = ComplexityAnalyzer()
        complexity_metrics = complexity_analyzer.analyze(parsed_ast)

        # Dependency graph
        dep_generator = DependencyGraphGenerator()
        dep_graph = dep_generator.generate_graph(parsed_ast)

        # HTML tree
        html_generator = HtmlTreeGenerator()
        html_tree = html_generator.generate_html(parsed_ast)

        # String patterns
        pattern_generator = StringDiagramGenerator()
        pattern_diagram = pattern_generator.generate_pattern_flow_diagram(parsed_ast)

        # All should succeed
        assert complexity_metrics.total_rules == 3
        assert isinstance(dep_graph, str)
        assert isinstance(html_tree, str)
        assert isinstance(pattern_diagram, str)

    def test_metrics_consistency(self, parsed_ast) -> None:
        """Test that different metrics report consistent counts."""
        # Complexity analysis
        complexity_analyzer = ComplexityAnalyzer()
        complexity_metrics = complexity_analyzer.analyze(parsed_ast)

        # Dependency analysis
        dep_generator = DependencyGraphGenerator()
        dep_generator.generate_graph(parsed_ast)  # Populate state
        dep_stats = dep_generator.get_dependency_stats()

        # Should report same rule counts
        assert complexity_metrics.total_rules == dep_stats["total_rules"]
        assert complexity_metrics.total_imports == dep_stats["total_imports"]

    def test_large_file_handling(self) -> None:
        """Test metrics on a larger, more complex YARA file."""
        # Create a more complex YARA file
        complex_yara = """
import "pe"
import "math"
import "hash"

rule ComplexRule1 : malware trojan {
    meta:
        author = "Test"
        family = "TestFamily"
    strings:
        $s1 = "test1" ascii wide nocase
        $s2 = "test2"
        $h1 = { 90 90 [1-3] AA BB ?? CC DD }
        $h2 = { (48 | 49 | 4A) 65 6C 6C 6F [4-8] 57 6F 72 6C 64 }
        $r1 = /test[a-z0-9]{1,10}/i
        $r2 = /^(GET|POST)\\s+/
    condition:
        pe.is_pe and pe.is_32bit() and (
            (2 of ($s*) and 1 of ($h*)) or
            (for any of ($r*) : ($ in (0..1024))) and
            (math.entropy(pe.entry_point, 256) > 6.5 or
             hash.md5(0, 1024) == "d41d8cd98f00b204e9800998ecf8427e")
        )
}

rule ComplexRule2 {
    strings:
        $a = { FF 25 [4] }
        $b = { E8 [4] }
    condition:
        for all i in (1..#a) : (
            @a[i] < pe.entry_point and
            for any j in (1..#b) : (
                @b[j] > @a[i] and @b[j] < @a[i] + 100
            )
        )
}

private rule HelperRule {
    condition:
        pe.number_of_sections > 3
}
        """

        parser = Parser()
        ast = parser.parse(complex_yara)

        # Run all metrics
        complexity_analyzer = ComplexityAnalyzer()
        metrics = complexity_analyzer.analyze(ast)

        dep_generator = DependencyGraphGenerator()
        dep_graph = dep_generator.generate_graph(ast)

        pattern_generator = StringDiagramGenerator()
        pattern_generator.get_pattern_statistics()

        # Verify complex analysis worked
        assert metrics.total_rules == 3
        assert metrics.max_condition_depth > 2  # Should be fairly deep
        assert len(metrics.cyclomatic_complexity) == 3
        assert isinstance(dep_graph, str)

        # Complex rules should be detected
        assert len(metrics.complex_rules) > 0
