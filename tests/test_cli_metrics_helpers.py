"""Tests for metrics CLI helper functions (no mocks)."""

from __future__ import annotations

from textwrap import dedent
from types import SimpleNamespace

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.cli.metrics_reporting import (
    _display_module_usage,
    _display_pattern_statistics,
    _display_rule_dependencies,
    _display_text_fallback,
    _display_text_pattern_analysis,
    _format_complexity_output,
    _format_string_analysis_output,
)
from yaraast.cli.metrics_string_services import _analyze_string_patterns
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.dependency_graph import DependencyGraphGenerator
from yaraast.metrics.graphviz_errors import is_graphviz_error
from yaraast.metrics.string_diagrams import StringDiagramGenerator
from yaraast.parser import Parser


def _parse_yara(code: str) -> YaraFile:
    parser = Parser()
    return parser.parse(dedent(code))


def test_metrics_helper_text_functions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = """
    import "pe"

    rule helper_rule {
        strings:
            $a = "abc"
        condition:
            $a and pe.number_of_sections > 0
    }
    """
    ast = _parse_yara(code)

    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)
    text = _format_complexity_output(metrics, "text")
    assert "YARA Rule Complexity Analysis" in text

    analysis = _analyze_string_patterns(ast)
    output_text = _format_string_analysis_output(analysis, "text")
    assert "YARA String Analysis" in output_text

    generator = DependencyGraphGenerator()
    generator.visit(ast)
    stats = generator.get_dependency_stats()
    text_graph = "\n".join(
        [
            "Dependency Analysis",
            "=" * 19,
            "",
            f"Total rules: {stats['total_rules']}",
            f"Total imports: {stats['total_imports']}",
            f"Rules with strings: {stats['rules_with_strings']}",
            f"Rules using modules: {stats['rules_using_modules']}",
            "",
            "Rule Dependencies:",
            *[
                f"  {rule} → {', '.join(sorted(dependencies))}"
                for rule, dependencies in sorted(generator.dependencies.items())
                if dependencies
            ],
        ]
    )
    assert "Dependency Analysis" in text_graph

    _display_text_fallback("rules.yar", ast, generator)
    captured = capsys.readouterr().out
    assert "Dependency Analysis" in captured


def test_string_pattern_analysis_preserves_duplicate_rule_names() -> None:
    ast = _parse_yara("""
        rule dup_first {
            strings:
                $a = "one"
            condition:
                $a
        }

        rule dup_second {
            strings:
                $b = "two"
            condition:
                $b
        }
        """)
    ast.rules[0].name = "dup"
    ast.rules[1].name = "dup"

    analysis = _analyze_string_patterns(ast)

    assert list(analysis["rules"]) == ["dup#1", "dup#2"]
    assert analysis["rules"]["dup#1"]["identifiers"] == ["$a"]
    assert analysis["rules"]["dup#2"]["identifiers"] == ["$b"]


def test_string_pattern_analysis_counts_empty_duplicate_rules_in_order() -> None:
    ast = _parse_yara("""
        rule dup_first {
            condition:
                true
        }

        rule dup_second {
            strings:
                $a = "one"
            condition:
                $a
        }
        """)
    ast.rules[0].name = "dup"
    ast.rules[1].name = "dup"

    analysis = _analyze_string_patterns(ast)

    assert list(analysis["rules"]) == ["dup#2"]
    assert analysis["rules"]["dup#2"]["identifiers"] == ["$a"]


def test_string_pattern_analysis_uses_utf8_byte_lengths() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="unicode_plain",
                strings=[PlainString(identifier="$u", value="á", modifiers=[])],
            )
        ]
    )

    analysis = _analyze_string_patterns(ast)

    assert analysis["length_stats"] == {"min": 2, "max": 2, "avg": 2.0}


def test_metrics_graphviz_error_detection() -> None:
    err = Exception("failed to execute PosixPath('dot')")
    assert is_graphviz_error(err) is True


def test_metrics_display_helpers_sort_set_backed_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    generator = SimpleNamespace(
        dependencies={
            "rule_z": {"dep_z", "dep_a", "dep_m", "dep_b", "dep_y", "dep_c"},
            "rule_a": {"dep_b", "dep_a"},
        },
        module_references={
            "rule_z": {"pe", "math", "dotnet", "elf"},
            "rule_a": {"pe", "elf"},
        },
    )

    _display_rule_dependencies(generator)
    _display_module_usage(generator)

    output = capsys.readouterr().out
    assert "  rule_a → dep_a, dep_b" in output
    assert "  rule_z → dep_a, dep_b, dep_c, dep_m, dep_y, dep_z" in output
    assert output.index("  rule_a →") < output.index("  rule_z →")
    assert "  rule_a uses: elf, pe" in output
    assert "  rule_z uses: dotnet, elf, math, pe" in output
    assert output.index("  rule_a uses:") < output.index("  rule_z uses:")

    text_graph = "\n".join(
        [
            "Dependency Analysis",
            "=" * 19,
            "",
            "Total rules: 2",
            "Total imports: 0",
            "Rules with strings: 0",
            "Rules using modules: 0",
            "",
            "Rule Dependencies:",
            *[
                f"  {rule} → {', '.join(sorted(dependencies))}"
                for rule, dependencies in sorted(generator.dependencies.items())
                if dependencies
            ],
        ]
    )
    assert "  rule_a → dep_a, dep_b" in text_graph
    assert "  rule_z → dep_a, dep_b, dep_c, dep_m, dep_y, dep_z" in text_graph
    assert text_graph.index("  rule_a →") < text_graph.index("  rule_z →")


def test_metrics_pattern_helpers(capsys: pytest.CaptureFixture[str]) -> None:
    code = """
    rule helper_patterns {
        strings:
            $a = "abc"
            $b = { 6A 40 ?? }
            $c = /ab+c/
        condition:
            any of them
    }
    """
    ast = _parse_yara(code)
    generator = StringDiagramGenerator()

    _display_text_pattern_analysis(generator, ast)
    _display_pattern_statistics(generator)
    output = capsys.readouterr().out
    assert "String Pattern Analysis" in output


def test_metrics_pattern_statistics_propagates_malformed_stats() -> None:
    generator = SimpleNamespace(get_pattern_statistics=lambda: {"total_patterns": 1})

    with pytest.raises(KeyError):
        _display_pattern_statistics(generator)
