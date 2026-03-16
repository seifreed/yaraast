"""Additional CLI benchmark/metrics/performance-check tests without mocks."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from yaraast.ast.base import ASTNode
from yaraast.cli.benchmark_tools import ASTBenchmarker
from yaraast.cli.commands.performance_check import performance_check
from yaraast.cli.metrics_reporting import (
    _display_graph_statistics,
    _display_graphviz_installation_help,
    _display_module_usage,
    _display_pattern_result,
    _display_pattern_statistics,
    _display_rule_dependencies,
    _display_successful_graph_result,
    _display_text_fallback,
    _display_text_pattern_analysis,
    _emit_text_output,
    _format_complexity_output,
    _format_complexity_text,
    _format_string_analysis_output,
    _format_strings_text,
    _get_text_graph,
    _graphviz_fallback_message,
    _output_string_analysis_results,
    build_report_summary,
    complexity_quality_message,
    display_report_completion,
    write_complexity_report_files,
    write_report_summary,
)
from yaraast.cli.metrics_services import MetricsReportData
from yaraast.cli.metrics_string_services import _analyze_string_patterns
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.string_diagrams import StringDiagramGenerator
from yaraast.parser import Parser

try:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    DependencyGraphGenerator = None


def _parse_yara(code: str) -> ASTNode:
    return Parser().parse(dedent(code))


def _sample_ast() -> ASTNode:
    return _parse_yara(
        """
        import "pe"

        rule dependency_target {
            condition:
                true
        }

        rule sample {
            strings:
                $a = "abcdef" nocase
                $b = { 4D 5A ?? 90 }
                $c = /ab+c/
            condition:
                dependency_target and $a and pe.is_pe
        }
        """,
    )


def test_ast_benchmarker_success_error_and_summary(tmp_path: Path) -> None:
    yara_path = tmp_path / "bench.yar"
    yara_path.write_text(
        dedent(
            """
            rule bench {
                strings:
                    $a = "abcdef"
                    $b = /ab+c/
                condition:
                    any of them
            }
            """,
        ).strip(),
        encoding="utf-8",
    )

    benchmarker = ASTBenchmarker()

    parsing = benchmarker.benchmark_parsing(yara_path, iterations=1)
    codegen = benchmarker.benchmark_codegen(yara_path, iterations=1)
    roundtrip = benchmarker.benchmark_roundtrip(yara_path, iterations=1)
    failed = benchmarker.benchmark_parsing(tmp_path / "missing.yar", iterations=1)
    failed_codegen = benchmarker.benchmark_codegen(tmp_path / "missing_codegen.yar", iterations=1)
    failed_roundtrip = benchmarker.benchmark_roundtrip(
        tmp_path / "missing_roundtrip.yar", iterations=1
    )

    assert parsing.success is True
    assert parsing.operation == "parsing"
    assert parsing.rules_count == 1
    assert parsing.strings_count == 2
    assert parsing.ast_nodes > 0

    assert codegen.success is True
    assert codegen.operation == "codegen"

    assert len(roundtrip) == 1
    assert roundtrip[0].success is True
    assert roundtrip[0].operation == "roundtrip"

    assert failed.success is False
    assert failed.error
    assert failed_codegen.success is False
    assert failed_roundtrip[0].success is False

    summary = benchmarker.get_benchmark_summary()
    assert summary["parsing"]["count"] == 1
    assert summary["codegen"]["count"] == 1
    assert summary["roundtrip"]["count"] == 1
    assert "avg_rules_per_second" in summary["parsing"]

    benchmarker.clear_results()
    assert benchmarker.results == []
    assert benchmarker.get_benchmark_summary() == {"message": "No benchmarks run"}

    failures_only = ASTBenchmarker()
    failures_only.benchmark_codegen(tmp_path / "missing_only_codegen.yar", iterations=1)
    failures_only.benchmark_roundtrip(tmp_path / "missing_only_roundtrip.yar", iterations=1)
    assert failures_only.get_benchmark_summary() == {}


def test_performance_check_no_issues_and_abort_paths(tmp_path: Path) -> None:
    runner = CliRunner()

    clean_rule = tmp_path / "clean.yar"
    clean_rule.write_text(
        dedent(
            """
            rule clean {
                strings:
                    $a = "abcdefghi"
                condition:
                    $a
            }
            """,
        ).strip(),
        encoding="utf-8",
    )

    result = runner.invoke(performance_check, [str(clean_rule), "--severity", "critical"])
    assert result.exit_code == 0
    assert "No performance issues found" in result.output

    result = runner.invoke(performance_check, [str(clean_rule), "--summary"])
    assert result.exit_code == 0
    assert "Performance Issue Summary" in result.output

    result = runner.invoke(performance_check, [str(tmp_path)])
    assert result.exit_code != 0
    assert "Error:" in result.output


def test_performance_check_displays_issues(tmp_path: Path) -> None:
    runner = CliRunner()
    issue_rule = tmp_path / "issues.yar"
    issue_rule.write_text(
        dedent(
            """
            rule issues {
                strings:
                    $a = "ab"
                condition:
                    $a
            }
            """,
        ).strip(),
        encoding="utf-8",
    )

    result = runner.invoke(performance_check, [str(issue_rule)])
    assert result.exit_code == 0
    assert "Performance Issues" in result.output
    assert "Suggestions:" in result.output
    assert "Found 1 performance issues" in result.output


def test_metrics_reporting_complexity_and_string_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ast = _sample_ast()
    metrics = ComplexityAnalyzer().analyze(ast)
    analysis = _analyze_string_patterns(ast)

    text = _format_complexity_text(metrics)
    assert "YARA Rule Complexity Analysis" in text
    assert "Complex Rules" in text or "File Metrics" in text

    metrics.complex_rules = ["sample"]
    metrics.unused_strings = [f"$u{i}" for i in range(11)]
    metrics.module_usage = {"pe": 1}
    rich_text = _format_complexity_text(metrics)
    assert "Heuristic Complexity Thresholds" in rich_text
    assert "Unused Strings:" in rich_text
    assert "... and 1 more" in rich_text
    assert "Module Usage:" in rich_text

    json_output = _format_complexity_output(metrics, "json")
    assert '"quality_score"' in json_output
    assert _format_complexity_output(metrics, "text").startswith("YARA Rule Complexity Analysis")

    warn_message, warn_ok = complexity_quality_message(10.0, 70)
    pass_message, pass_ok = complexity_quality_message(90.0, 70)
    assert warn_ok is False and "warning" in warn_message.lower()
    assert pass_ok is True and "passed" in pass_message.lower()

    complexity_path = tmp_path / "complexity.txt"
    _emit_text_output(text, str(complexity_path), "Complexity metrics written to")
    _emit_text_output("inline complexity", None, "unused")

    string_text = _format_strings_text(analysis)
    assert "YARA String Analysis" in string_text
    assert "Modifiers:" in string_text
    assert "Hex patterns: 1" in string_text

    assert _format_string_analysis_output(analysis, "json").startswith("{")
    assert _format_string_analysis_output(analysis, "text").startswith("YARA String Analysis")

    string_path = tmp_path / "strings.txt"
    _output_string_analysis_results(string_text, str(string_path))
    _output_string_analysis_results("inline strings", None)

    captured = capsys.readouterr().out
    assert "Complexity metrics written to" in captured
    assert "inline complexity" in captured
    assert "String analysis written to" in captured
    assert "inline strings" in captured
    assert complexity_path.read_text(encoding="utf-8").startswith("YARA Rule Complexity Analysis")
    assert string_path.read_text(encoding="utf-8").startswith("YARA String Analysis")


def test_metrics_reporting_graph_and_pattern_helpers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    if DependencyGraphGenerator is None:
        pytest.skip("graphviz package is not installed")
    ast = _sample_ast()

    dep_generator = DependencyGraphGenerator()
    dep_generator.visit(ast)
    dep_generator.dependencies["sample"].add("dependency_target")
    dep_generator.dependencies["dependency_target"] = set()
    dep_generator.module_references["sample"].add("pe")

    stats = dep_generator.get_dependency_stats()
    text_graph = _get_text_graph(stats, dep_generator.dependencies)
    assert "Dependency Analysis" in text_graph
    assert "Total rules: 2" in text_graph
    assert "sample → dependency_target" in text_graph

    _display_graph_statistics(dep_generator)
    _display_rule_dependencies(dep_generator)
    _display_module_usage(dep_generator)
    _display_graphviz_installation_help()
    _display_text_fallback("sample.yar", ast, dep_generator)

    output_file = tmp_path / "deps.dot"
    output_file.write_text("digraph {}", encoding="utf-8")
    _display_successful_graph_result(str(output_file), dep_generator)
    _display_successful_graph_result(str(output_file), None)
    _display_successful_graph_result(str(tmp_path / "missing.dot"), dep_generator)
    _display_pattern_result(str(output_file))
    _display_pattern_result("digraph { a -> b }")

    pattern_generator = StringDiagramGenerator()
    _display_text_pattern_analysis(pattern_generator, ast)
    _display_pattern_statistics(pattern_generator)
    _display_pattern_statistics(
        type(
            "ShortStats",
            (),
            {
                "get_pattern_statistics": lambda self: {
                    "total_patterns": 1,
                    "by_type": {"plain": 1},
                    "complexity_distribution": {"low": 1},
                },
            },
        )(),
    )

    out = capsys.readouterr().out
    assert "Graph Statistics:" in out
    assert "Rule Dependencies:" in out
    assert "Module Usage:" in out
    assert "String Pattern Analysis" in out
    assert "Pattern diagram generated" in out
    assert "Diagram source:" in out
    assert "Dependency graph generated" in out
    assert _graphviz_fallback_message("text analysis").startswith("⚠️")


def test_metrics_reporting_direct_display_helpers(capsys: pytest.CaptureFixture[str]) -> None:
    class _Plain:
        identifier = "$p"
        value = "x" * 40

    class _Hex:
        identifier = "$h"
        tokens = [1, 2, 3]

    class _Regex:
        identifier = "$r"
        regex = "ab+"

    _display_pattern_result("digraph { a -> b }")
    _display_graphviz_installation_help()
    _display_pattern_statistics(
        type("NoStats", (), {"get_pattern_statistics": lambda self: None})()
    )
    _display_pattern_statistics(
        type(
            "BadStats",
            (),
            {"get_pattern_statistics": lambda self: (_ for _ in ()).throw(AttributeError("boom"))},
        )(),
    )

    from yaraast.cli.metrics_reporting import (
        _display_hex_string,
        _display_pattern_summary,
        _display_plain_string,
        _display_regex_string,
        _display_text_statistics,
    )

    _display_plain_string(_Plain())
    _display_hex_string(_Hex())
    _display_regex_string(_Regex())
    _display_text_statistics(
        "sample.yar",
        {
            "total_rules": 2,
            "total_imports": 1,
            "rules_with_strings": 1,
            "rules_using_modules": 1,
        },
    )
    _display_pattern_summary({"plain": 1, "hex": 1, "regex": 1})

    out = capsys.readouterr().out
    assert '"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx..."' in out
    assert "HEX pattern (3 tokens)" in out
    assert "/ab+/" in out
    assert "Total strings: 3" in out


def test_metrics_reporting_analyze_pattern_counts_and_string_branches(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ast = _sample_ast()
    from yaraast.cli.metrics_reporting import _analyze_pattern_counts

    counts = _analyze_pattern_counts(ast)
    assert counts == {"plain": 1, "hex": 1, "regex": 1}

    analysis = {
        "total_strings": 3,
        "type_distribution": {"plain": 1, "hex": 1, "regex": 1},
        "length_stats": {"min": 2, "max": 6, "avg": 4.0},
        "modifiers": {"nocase": 1},
        "patterns": {"short_strings": 1, "hex_patterns": 2},
    }
    text = _format_strings_text(analysis)
    assert "Short strings (<4 chars): 1" in text
    assert "Hex patterns: 2" in text
    assert "nocase: 1" in text

    _output_string_analysis_results("analysis text", None)
    assert "analysis text" in capsys.readouterr().out


def test_metrics_reporting_empty_and_mixed_branches(capsys: pytest.CaptureFixture[str]) -> None:
    if DependencyGraphGenerator is None:
        pytest.skip("graphviz package is not installed")
    empty_ast = _parse_yara("rule empty { condition: true }")
    empty_metrics = ComplexityAnalyzer().analyze(empty_ast)
    text = _format_complexity_text(empty_metrics)
    assert "Cyclomatic Complexity by Rule:" in text
    assert "Heuristic Complexity Thresholds:" not in text
    assert "Unused Strings:" not in text
    assert "Module Usage:" not in text

    dep_generator = DependencyGraphGenerator()
    dep_generator.dependencies["a"] = set()
    dep_generator.module_references["a"] = set()
    _display_rule_dependencies(dep_generator)
    _display_module_usage(dep_generator)

    assert _get_text_graph(
        {
            "total_rules": 1,
            "total_imports": 0,
            "rules_with_strings": 0,
            "rules_using_modules": 0,
        },
        {"a": [], "b": ["c"]},
    ).endswith("  b → c")

    counts = _analyze_string_patterns(empty_ast)
    plain = _format_strings_text(counts)
    assert "Modifiers:" not in plain
    assert "Short strings" not in plain
    assert "Hex patterns" not in plain

    out = capsys.readouterr().out
    assert "Rule Dependencies:" in out
    assert "Module Usage:" in out


def test_metrics_reporting_report_files_and_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ast = _sample_ast()
    metrics = ComplexityAnalyzer().analyze(ast)

    generated = write_complexity_report_files(tmp_path, "sample", metrics)
    assert generated == ["sample_complexity.json", "sample_complexity.txt"]
    assert (tmp_path / generated[0]).exists()
    assert (tmp_path / generated[1]).exists()

    report_data = MetricsReportData(
        base_name="sample",
        complexity_metrics=metrics,
        complexity_payload={},
        generated_files=["tree.html"],
    )
    summary = build_report_summary("sample.yar", report_data, generated)
    assert summary["file"] == "sample.yar"
    assert summary["metrics"]["total_rules"] == metrics.total_rules
    assert len(summary["generated_files"]) == 3

    write_report_summary(tmp_path, summary)
    assert (tmp_path / "summary.json").exists()

    display_report_completion(tmp_path, summary, metrics)
    out = capsys.readouterr().out
    assert "Comprehensive report generated" in out
    assert "Quality Score" in out
    assert "Generated 3 files" in out
