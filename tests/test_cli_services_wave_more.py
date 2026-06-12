"""Coverage wave for CLI service/reporting helpers (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from yaraast.analysis.best_practices import AnalysisReport, Suggestion
from yaraast.analysis.optimization import OptimizationReport, OptimizationSuggestion
from yaraast.cli import (
    analyze_services as an,
    bench_services as bs,
    performance_check_reporting as pcr,
    workspace_services as ws,
)
from yaraast.performance.string_analyzer import StringPerformanceIssue


def test_analyze_services_formatting_helpers() -> None:
    bp = AnalysisReport(
        statistics={"rules": 2},
        suggestions=[
            Suggestion(
                rule_name="r1",
                category="security",
                severity="error",
                message="bad",
                location="line 1",
            ),
            Suggestion(
                rule_name="r2",
                category="style",
                severity="warning",
                message="meh",
                location="line 2",
            ),
        ],
    )
    opt = OptimizationReport(
        statistics={"suggestions": 1},
        suggestions=[
            OptimizationSuggestion(
                rule_name="r1",
                optimization_type="dedup",
                impact="high",
                description="improve",
                code_before="a",
                code_after="b",
            ),
        ],
    )

    errors, warnings, info = an._get_severity_counts(bp)
    assert len(errors) == 1 and len(warnings) == 1 and len(info) == 0

    assert an._filter_suggestions(bp.suggestions, "all") == bp.suggestions
    assert len(an._filter_suggestions(bp.suggestions, "security")) == 1

    data = an._generate_json_report("sample.yar", bp, opt)
    assert data["file"] == "sample.yar"
    assert data["best_practices"]["statistics"] == {"rules": 2}
    assert data["optimization"]["suggestions"][0]["type"] == "dedup"

    text = an._generate_text_report("sample.yar", bp, opt)
    assert "BEST PRACTICES" in text
    assert "OPTIMIZATIONS" in text
    assert "SUMMARY" in text
    assert "Total issues:" in text

    assert an._get_level_style("high") == "red"
    assert an._get_level_style("medium") == "yellow"
    assert an._get_level_style("low") == "blue"
    assert an._get_level_style("other") == "white"


def test_bench_services_operations_and_summary() -> None:
    class _Result:
        def __init__(self, success: bool) -> None:
            self.success = success

    class _Bench:
        def benchmark_parsing(self, *_args: object) -> _Result:
            return _Result(True)

        def benchmark_codegen(self, *_args: object) -> _Result:
            return _Result(False)

        def benchmark_roundtrip(self, *_args: object) -> list[_Result]:
            return [_Result(True)]

        def get_benchmark_summary(self) -> dict[str, int]:
            return {"total": 3}

    bench = _Bench()
    path = Path("/tmp/rule.yar")

    assert bs._determine_operations_to_run("all") == ["parse", "codegen", "roundtrip"]
    assert bs._determine_operations_to_run("roundtrip") == ["roundtrip"]
    assert bs._determine_operations_to_run("parse") == ["parse"]

    assert bs._run_single_operation(bench, path, "parse", 2).success is True
    assert bs._run_single_operation(bench, path, "codegen", 2).success is False
    assert bs._run_single_operation(bench, path, "roundtrip", 2).success is True

    for invalid_operation in [None, 123]:
        with pytest.raises(TypeError, match="benchmark operation must be a string"):
            bs._determine_operations_to_run(invalid_operation)
        with pytest.raises(TypeError, match="benchmark operation must be a string"):
            bs._run_single_operation(bench, path, invalid_operation, 2)

    for unknown_operation in ["", "unknown"]:
        with pytest.raises(
            ValueError,
            match="benchmark operation must be one of: all, codegen, parse, roundtrip",
        ):
            bs._determine_operations_to_run(unknown_operation)
        with pytest.raises(
            ValueError,
            match="benchmark operation must be one of: codegen, parse, roundtrip",
        ):
            bs._run_single_operation(bench, path, unknown_operation, 2)

    file_results = bs._run_benchmarks_for_single_file(bench, path, "all", 3)
    assert "parse" in file_results
    assert "roundtrip" in file_results
    assert "codegen" not in file_results

    all_results = bs._run_benchmarks_for_all_files(bench, [path], "all", 1)
    assert all_results[0]["file_name"] == "rule.yar"
    assert bs._get_benchmark_summary(bench)["total"] == 3


def test_workspace_services_formatters() -> None:
    dep = SimpleNamespace(
        export_dot=lambda: "digraph G {}",
        nodes={
            "a": SimpleNamespace(
                type="rule",
                dependencies={"b"},
                dependents=set(),
                metadata={"x": 1},
            ),
        },
    )
    file_result = SimpleNamespace(
        errors=["e1"],
        warnings=["w1"],
        type_errors=["t1"],
        analysis_results={"k": "v"},
    )
    report = SimpleNamespace(
        files_analyzed=1,
        total_rules=2,
        total_includes=0,
        total_imports=1,
        global_errors=["g1"],
        file_results={"/tmp/a.yar": file_result},
        statistics={
            "total_errors": 1,
            "total_warnings": 1,
            "total_type_errors": 1,
            "cycles": 0,
            "rule_name_conflicts": 0,
        },
        dependency_graph=dep,
    )

    txt = ws.format_workspace_report_text(report)
    assert "Workspace Analysis Report" in txt
    assert "Global Errors:" in txt
    assert "Type Errors:" in txt

    js = ws.format_workspace_report_json(report)
    assert '"global_errors"' in js

    dot = ws.format_workspace_graph(report, "dot")
    assert "digraph" in dot

    graph_json = ws.format_workspace_graph(report, "json")
    assert '"nodes"' in graph_json

    assert ws.format_workspace_output(report, "json") == js
    assert ws.format_workspace_output(report, "dot") == dot
    assert "Workspace Analysis Report" in ws.format_workspace_output(report, "text")

    for invalid_format in [None, 123]:
        with pytest.raises(TypeError, match="workspace graph format must be a string"):
            ws.format_workspace_graph(report, invalid_format)
        with pytest.raises(TypeError, match="workspace output format must be a string"):
            ws.format_workspace_output(report, invalid_format)

    for unknown_format in ["", "xml", "yaml"]:
        with pytest.raises(ValueError, match="workspace graph format must be one of: dot, json"):
            ws.format_workspace_graph(report, unknown_format)
        with pytest.raises(
            ValueError,
            match="workspace output format must be one of: dot, json, text",
        ):
            ws.format_workspace_output(report, unknown_format)


def test_workspace_graph_json_lists_are_stably_sorted() -> None:
    dep = SimpleNamespace(
        export_dot=lambda: "digraph G {}",
        nodes={
            "z_node": SimpleNamespace(
                type="rule",
                dependencies={"z_dep", "a_dep"},
                dependents={"z_parent", "a_parent"},
                metadata={},
            ),
            "a_node": SimpleNamespace(
                type="rule",
                dependencies=set(),
                dependents=set(),
                metadata={},
            ),
        },
    )
    report = SimpleNamespace(dependency_graph=dep)

    data = json.loads(ws.format_workspace_graph(report, "json"))

    assert list(data["nodes"]) == ["a_node", "z_node"]
    assert data["nodes"]["z_node"]["dependencies"] == ["a_dep", "z_dep"]
    assert data["nodes"]["z_node"]["dependents"] == ["a_parent", "z_parent"]


def test_performance_check_reporting_render() -> None:
    console = Console(record=True, width=120)
    issues = [
        StringPerformanceIssue(
            rule_name="r1",
            string_id="$a",
            issue_type="dup",
            severity="critical",
            description="duplicate",
            suggestion="merge",
        ),
        StringPerformanceIssue(
            rule_name="r2",
            string_id="$b",
            issue_type="slow_regex",
            severity="medium",
            description="slow",
            suggestion="anchor",
        ),
    ]

    pcr.display_parse_failure(console)
    pcr.display_no_issues(console)
    pcr.display_issues(console, issues)
    pcr.display_summary(
        console,
        issue_types={
            "dup": {"count": 1, "critical": 1, "rules": {"r1"}},
            "slow_regex": {"count": 1, "critical": 0, "rules": {"r2"}},
        },
        total_rules=4,
        issues=issues,
    )
    pcr.display_issue_totals(console, issues)

    out = console.export_text()
    assert "Failed to parse" in out
    assert "No performance issues found" in out
    assert "Performance Issues" in out
    assert "Suggestions:" in out
    assert "Performance Issue Summary" in out
    assert "Rules with issues" in out
    assert "critical issues" in out


def test_performance_check_suggestions_are_sorted() -> None:
    console = Console(record=True, width=120)
    issues = [
        StringPerformanceIssue(
            rule_name=f"r{index}",
            string_id="$a",
            issue_type="perf",
            severity="medium",
            description="desc",
            suggestion=suggestion,
        )
        for index, suggestion in enumerate(
            ["z suggestion", "a suggestion", "m suggestion", "b suggestion"],
            start=1,
        )
    ]

    pcr.display_issues(console, issues)

    out = console.export_text()
    assert out.index("a suggestion") < out.index("b suggestion")
    assert out.index("b suggestion") < out.index("m suggestion")
    assert out.index("m suggestion") < out.index("z suggestion")


def test_performance_check_reporting_escapes_markup_in_dynamic_values() -> None:
    console = Console(record=True, width=120)
    bad = "bad[/red][broken"
    issues = [
        StringPerformanceIssue(
            rule_name=bad,
            string_id=bad,
            issue_type=bad,
            severity=bad,
            description=bad,
            suggestion=bad,
        )
    ]

    pcr.display_issues(console, issues)
    pcr.display_summary(
        console,
        issue_types={bad: {"count": 1, "critical": 0, "rules": {bad}}},
        total_rules=1,
        issues=issues,
    )

    out = console.export_text()
    assert bad in out
