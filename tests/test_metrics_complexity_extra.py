"""Additional real tests for complexity metrics (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.complexity_helpers import (
    calculate_cognitive_complexity,
    calculate_cyclomatic_complexity,
    calculate_expression_complexity,
    calculate_rule_complexity,
)
from yaraast.metrics.complexity_reporting import analyze_file_complexity, generate_complexity_report
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


def test_complexity_analyzer_metrics_and_report(tmp_path: Path) -> None:
    code = """
    import "pe"

    rule complex_rule : tag1 tag2 {
        meta:
            author = "me"
            description = "desc"
        strings:
            $a = "abc" nocase
            $b = /ab+c/ wide
            $c = { 6A 40 ?? }
        condition:
            for any of ($a,$b,$c) : ( #a > 0 and pe.number_of_sections > 0 )
    }

    rule simple_rule {
        condition:
            true
    }
    """
    parser = Parser()
    ast = parser.parse(dedent(code))

    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    assert metrics.total_rules == 2
    assert metrics.total_imports == 1
    assert metrics.rules_with_meta == 1
    assert metrics.rules_with_tags == 1
    assert metrics.rules_with_strings == 1
    assert metrics.total_strings >= 3
    assert metrics.plain_strings >= 1
    assert metrics.regex_strings >= 1
    assert metrics.hex_strings >= 1
    assert metrics.strings_with_modifiers >= 1
    assert metrics.for_of_expressions >= 1
    assert metrics.total_binary_ops >= 1

    report = generate_complexity_report(ast)
    assert report["summary"]["total_rules"] == 2
    assert report["summary"]["quality_grade"] in {"A", "B", "C", "D", "F"}

    # Exercise file-based analysis
    path = tmp_path / "rules.yar"
    path.write_text(dedent(code), encoding="utf-8")
    file_report = analyze_file_complexity(path)
    assert file_report["file"] == str(path)
    assert file_report["complexity"]["summary"]["total_rules"] == 2


def test_complexity_calculators_on_rule_and_condition() -> None:
    code = """
    rule calc_rule {
        strings:
            $a = "abc"
        condition:
            not ($a) or (1 == 1)
    }
    """
    parser = Parser()
    ast = parser.parse(dedent(code))
    rule = ast.rules[0]
    assert rule.condition is not None

    total = calculate_rule_complexity(rule)
    expr_complexity = calculate_expression_complexity(rule.condition)
    cyclomatic = calculate_cyclomatic_complexity(rule.condition)
    cognitive = calculate_cognitive_complexity(rule.condition)

    assert total > 0
    assert expr_complexity > 0
    assert cyclomatic >= 1
    assert cognitive > 0


def test_complexity_unused_strings_and_complex_rules() -> None:
    code = """
    rule complex_unused {
        strings:
            $a = "aaa"
            $b = /(a+)(b+)c*/
        condition:
            ( $a or $a ) and ( $a or $a ) and ( $a or $a ) and ( $a or $a )
    }
    """
    parser = Parser()
    ast = parser.parse(dedent(code))

    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    assert metrics.unused_strings  # $b unused
    assert any("complex_unused:$b" in s for s in metrics.unused_strings)
    assert metrics.regex_groups >= 1
    assert metrics.regex_quantifiers >= 1
    assert "complex_unused" in metrics.complex_rules or metrics.max_condition_depth >= 1


def test_complexity_unused_strings_are_stably_sorted() -> None:
    code = """
    rule sorted_unused {
        strings:
            $z = "z"
            $a = "a"
            $m = "m"
        condition:
            false
    }
    """
    ast = Parser().parse(dedent(code))

    metrics = ComplexityAnalyzer().analyze(ast)

    assert metrics.unused_strings == [
        "sorted_unused:$a",
        "sorted_unused:$m",
        "sorted_unused:$z",
    ]


def test_complexity_string_usage_tracks_condition_string_forms() -> None:
    code = """
    rule indirect_string_usage {
        strings:
            $counted = "counted"
            $positioned = "positioned"
            $ranged = "ranged"
            $grouped = "grouped"
            $wild_one = "wild one"
            $wild_two = "wild two"
        condition:
            #counted > 0 and
            $positioned at 0 and
            $ranged in (0..filesize) and
            any of ($grouped) and
            all of ($wild*)
    }
    """
    ast = Parser().parse(dedent(code))

    metrics = ComplexityAnalyzer().analyze(ast)

    assert metrics.unused_strings == []
    assert metrics.string_dependencies["indirect_string_usage"] == {
        "$counted",
        "$positioned",
        "$ranged",
        "$grouped",
        "$wild_one",
        "$wild_two",
    }


def test_complexity_string_usage_ignores_rule_wildcard_sets() -> None:
    code = """
    rule alpha_one {
        condition:
            true
    }

    rule alpha_two {
        condition:
            true
    }

    rule holder {
        strings:
            $alpha_local = "needle"
        condition:
            any of (alpha*)
    }
    """
    ast = Parser().parse(dedent(code))

    metrics = ComplexityAnalyzer().analyze(ast)

    assert metrics.string_dependencies.get("holder", set()) == set()
    assert metrics.unused_strings == ["holder:$alpha_local"]


def test_complexity_metrics_preserve_duplicate_rule_occurrences() -> None:
    code = """
    rule dup_first {
        strings:
            $a = "a"
            $unused_first = "unused"
        condition:
            $a
    }

    rule dup_second {
        strings:
            $b = "b"
            $unused_second = "unused"
        condition:
            $b
    }
    """
    ast = Parser().parse(dedent(code))
    ast.rules[0].name = "dup"
    ast.rules[1].name = "dup"

    metrics = ComplexityAnalyzer().analyze(ast)

    assert set(metrics.cyclomatic_complexity) == {"dup#1", "dup#2"}
    assert metrics.string_dependencies == {"dup#1": {"$a"}, "dup#2": {"$b"}}
    assert metrics.unused_strings == ["dup#1:$unused_first", "dup#2:$unused_second"]


def test_complexity_string_usage_tracks_offset_and_length_index_expressions() -> None:
    code = """
    rule indexed_string_usage {
        strings:
            $a = "a"
            $b = "b"
            $c = "c"
        condition:
            @a[#b] >= 0 and !a[#c] > 0
    }
    """
    ast = Parser().parse(dedent(code))

    metrics = ComplexityAnalyzer().analyze(ast)

    assert metrics.unused_strings == []
    assert metrics.string_dependencies["indexed_string_usage"] == {"$a", "$b", "$c"}


def test_complexity_string_usage_respects_yarax_with_local_shadowing() -> None:
    code = """
    rule shadowed_string {
        strings:
            $a = "value"
        condition:
            with $a = 1: $a > 0
    }

    rule declaration_value_uses_string {
        strings:
            $a = "value"
        condition:
            with local = $a: local
    }
    """
    ast = parse_yara_source(dedent(code))

    metrics = ComplexityAnalyzer().analyze(ast)

    assert "shadowed_string:$a" in metrics.unused_strings
    assert "shadowed_string" not in metrics.string_dependencies
    assert "declaration_value_uses_string:$a" not in metrics.unused_strings
    assert metrics.string_dependencies["declaration_value_uses_string"] == {"$a"}


def test_complexity_analyzer_counts_yarax_condition_nodes() -> None:
    code = """
    rule yarax_complexity {
        condition:
            with xs = [1, 2]: match xs {
                1 => pe.number_of_sections > 3,
                _ => false,
            }
    }
    """
    ast = parse_yara_source(dedent(code))

    metrics = ComplexityAnalyzer().analyze(ast)

    assert metrics.max_condition_depth >= 2
    assert metrics.total_binary_ops == 1
    assert metrics.cyclomatic_complexity["yarax_complexity"] > 1
    assert ast.rules[0].condition is not None
    assert calculate_expression_complexity(ast.rules[0].condition) > 0


def test_analyze_file_complexity_accepts_yarax_syntax(tmp_path: Path) -> None:
    path = tmp_path / "native_yarax.yar"
    path.write_text(
        "rule x { condition: with xs = [1]: match xs { _ => true } }",
        encoding="utf-8",
    )

    report = analyze_file_complexity(path)

    assert report["file"] == str(path)
    assert report["complexity"]["summary"]["total_rules"] == 1


def test_complexity_complex_rules_use_current_rule_depth_only() -> None:
    code = """
    rule deep {
        condition:
            ((((((((true and true) and true) and true) and true) and true) and true) and true) and true)
    }

    rule shallow {
        condition:
            true
    }
    """
    ast = Parser().parse(dedent(code))

    metrics = ComplexityAnalyzer().analyze(ast)

    assert "deep" in metrics.complex_rules
    assert "shallow" not in metrics.complex_rules
