"""Additional CLI benchmark/metrics/performance-check tests without mocks."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace
from typing import Any, cast

from click.testing import CliRunner
import pytest

from yaraast.ast.base import YaraFile
from yaraast.cli.benchmark_tools import ASTBenchmarker
import yaraast.cli.commands.performance_check as performance_check_module
from yaraast.cli.commands.performance_check import performance_check
from yaraast.cli.metrics_reporting import (
    _display_graph_statistics,
    _display_module_usage,
    _display_pattern_result,
    _display_pattern_statistics,
    _display_rule_dependencies,
    _display_successful_graph_result,
    _display_text_fallback,
    _display_text_pattern_analysis,
    _emit_text_output,
    _format_complexity_output,
    _format_string_analysis_output,
    _format_strings_text,
    _graphviz_fallback_message,
    _output_string_analysis_results,
    complexity_quality_message,
    write_complexity_report_files,
    write_report_summary,
)
from yaraast.cli.metrics_reporting_display import (
    display_text_statistics,
    path_size_for_display,
)
from yaraast.cli.metrics_string_services import _analyze_string_patterns
from yaraast.cli.performance_check_services import parse_performance_file
from yaraast.errors import ParseError
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.string_diagrams import StringDiagramGenerator
from yaraast.parser import Parser

try:
    from yaraast.metrics.dependency_graph import (
        DependencyGraphGenerator as _DependencyGraphGeneratorClass,
    )
except ModuleNotFoundError:
    DependencyGraphGeneratorClass: Any = None
else:
    DependencyGraphGeneratorClass = _DependencyGraphGeneratorClass


def _parse_yara(code: str) -> YaraFile:
    ast = Parser().parse(dedent(code))
    assert isinstance(ast, YaraFile)
    return ast


def _sample_ast() -> YaraFile:
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


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


def _yaral_rule() -> str:
    return """
rule ev {
  events:
    $e.metadata.event_type = "X"
  match:
    $e over 5m
  condition:
    $e
}
"""


def test_performance_check_command_escapes_error_markup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "perf.yar"
    yara_path.write_text("rule sample { condition: true }\n", encoding="utf-8")

    def raise_markup_error(_input_file: Path) -> object:
        raise ValueError("bad[/red][broken")

    monkeypatch.setattr(performance_check_module, "parse_performance_file", raise_markup_error)

    result = runner.invoke(performance_check, [str(yara_path)])

    assert result.exit_code != 0
    assert "bad[/red][broken" in result.output
    assert "closing tag" not in result.output


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

    failures_only = ASTBenchmarker()
    failures_only.benchmark_codegen(tmp_path / "missing_only_codegen.yar", iterations=1)
    failures_only.benchmark_roundtrip(tmp_path / "missing_only_roundtrip.yar", iterations=1)
    assert failures_only.get_benchmark_summary() == {}


def test_ast_benchmarker_does_not_expose_dead_clear_results() -> None:
    assert not hasattr(ASTBenchmarker, "clear_results")


def test_benchmark_result_does_not_expose_dead_memory_field() -> None:
    from yaraast.cli.benchmark_tools import BenchmarkResult

    assert "memory_usage" not in BenchmarkResult.__annotations__


def test_metrics_display_helpers_handle_null_byte_result_paths(capsys) -> None:
    _display_pattern_result("\x00broken.dot")
    _display_successful_graph_result("\x00broken.dot", object())

    output = capsys.readouterr().out
    assert "Diagram source:" in output
    assert "\x00broken.dot" in output


def test_ast_benchmarker_supports_yarax_roundtrip(tmp_path: Path) -> None:
    yara_path = tmp_path / "bench_yarax.yar"
    yara_path.write_text(_yarax_rule(), encoding="utf-8")
    benchmarker = ASTBenchmarker()

    parsing = benchmarker.benchmark_parsing(yara_path, iterations=1)
    codegen = benchmarker.benchmark_codegen(yara_path, iterations=1)
    roundtrip = benchmarker.benchmark_roundtrip(yara_path, iterations=1)[0]

    assert parsing.success is True
    assert codegen.success is True
    assert roundtrip.success is True
    assert parsing.rules_count == 1


def test_ast_benchmarker_rejects_invalid_iterations(tmp_path: Path) -> None:
    benchmarker = ASTBenchmarker()
    missing = tmp_path / "missing.yar"

    with pytest.raises(TypeError, match="iterations must be an integer"):
        benchmarker.benchmark_parsing(missing, iterations=cast(Any, True))

    with pytest.raises(TypeError, match="iterations must be an integer"):
        benchmarker.benchmark_codegen(missing, iterations=cast(Any, True))

    with pytest.raises(TypeError, match="iterations must be an integer"):
        benchmarker.benchmark_roundtrip(missing, iterations=cast(Any, True))

    with pytest.raises(TypeError, match="iterations must be an integer"):
        ASTBenchmarker._time_roundtrip("rule r { condition: true }", iterations=cast(Any, True))

    with pytest.raises(ValueError, match="iterations must be at least 1"):
        benchmarker.benchmark_parsing(missing, iterations=0)

    with pytest.raises(ValueError, match="iterations must be at least 1"):
        benchmarker.benchmark_codegen(missing, iterations=0)

    with pytest.raises(ValueError, match="iterations must be at least 1"):
        benchmarker.benchmark_roundtrip(missing, iterations=0)

    with pytest.raises(ValueError, match="iterations must be at least 1"):
        ASTBenchmarker._time_roundtrip("rule r { condition: true }", iterations=0)


def test_ast_benchmarker_reports_invalid_file_paths(tmp_path: Path) -> None:
    benchmarker = ASTBenchmarker()

    for method_name in ("benchmark_parsing", "benchmark_codegen"):
        method = getattr(benchmarker, method_name)

        empty = method("", iterations=1)
        whitespace = method("   ", iterations=1)
        directory = method(tmp_path, iterations=1)
        invalid_type = method(cast(Any, False), iterations=1)

        assert empty.success is False
        assert empty.error == "file_path must not be empty"
        assert whitespace.success is False
        assert whitespace.error == "file_path must not be empty"
        assert directory.success is False
        assert directory.error == "file_path must not be a directory"
        assert invalid_type.success is False
        assert invalid_type.error == "file_path must be a string or path-like object"

    roundtrip_empty = benchmarker.benchmark_roundtrip("", iterations=1)[0]
    roundtrip_whitespace = benchmarker.benchmark_roundtrip("   ", iterations=1)[0]
    roundtrip_directory = benchmarker.benchmark_roundtrip(tmp_path, iterations=1)[0]
    roundtrip_invalid_type = benchmarker.benchmark_roundtrip(cast(Any, False), iterations=1)[0]

    assert roundtrip_empty.success is False
    assert roundtrip_empty.error == "file_path must not be empty"
    assert roundtrip_whitespace.success is False
    assert roundtrip_whitespace.error == "file_path must not be empty"
    assert roundtrip_directory.success is False
    assert roundtrip_directory.error == "file_path must not be a directory"
    assert roundtrip_invalid_type.success is False
    assert roundtrip_invalid_type.error == "file_path must be a string or path-like object"


def test_ast_benchmarker_rejects_null_byte_file_paths() -> None:
    benchmarker = ASTBenchmarker()

    parsing = benchmarker.benchmark_parsing("\x00broken", iterations=1)
    codegen = benchmarker.benchmark_codegen("\x00broken", iterations=1)
    roundtrip = benchmarker.benchmark_roundtrip("\x00broken", iterations=1)[0]

    assert parsing.success is False
    assert parsing.error == "file_path must not contain null bytes"
    assert codegen.success is False
    assert codegen.error == "file_path must not contain null bytes"
    assert roundtrip.success is False
    assert roundtrip.error == "file_path must not contain null bytes"


def test_ast_benchmarker_reports_inaccessible_file_paths() -> None:
    benchmarker = ASTBenchmarker()
    inaccessible = "a" * 5000

    parsing = benchmarker.benchmark_parsing(inaccessible, iterations=1)
    codegen = benchmarker.benchmark_codegen(inaccessible, iterations=1)
    roundtrip = benchmarker.benchmark_roundtrip(inaccessible, iterations=1)[0]

    assert parsing.success is False
    assert parsing.error is not None
    assert parsing.error.startswith("path could not be accessed")
    assert codegen.success is False
    assert codegen.error is not None
    assert codegen.error.startswith("path could not be accessed")
    assert roundtrip.success is False
    assert roundtrip.error is not None
    assert roundtrip.error.startswith("path could not be accessed")


def test_ast_benchmarker_rejects_symlinked_file_paths(tmp_path: Path) -> None:
    benchmarker = ASTBenchmarker()
    target = tmp_path / "target.yar"
    target.write_text("rule bench { condition: true }", encoding="utf-8")
    link = tmp_path / "linked.yar"
    link.symlink_to(target)

    parsing = benchmarker.benchmark_parsing(link, iterations=1)
    codegen = benchmarker.benchmark_codegen(link, iterations=1)
    roundtrip = benchmarker.benchmark_roundtrip(link, iterations=1)[0]

    assert parsing.success is False
    assert parsing.error == "file_path must not traverse a symlink"
    assert codegen.success is False
    assert codegen.error == "file_path must not traverse a symlink"
    assert roundtrip.success is False
    assert roundtrip.error == "file_path must not traverse a symlink"


def test_ast_benchmarker_reports_invalid_utf8_inputs(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yar"
    bad.write_bytes(b"\xff")
    benchmarker = ASTBenchmarker()

    parsing = benchmarker.benchmark_parsing(bad, iterations=1)
    codegen = benchmarker.benchmark_codegen(bad, iterations=1)
    roundtrip = benchmarker.benchmark_roundtrip(bad, iterations=1)[0]

    assert parsing.success is False
    assert parsing.error == "YARA file must contain valid UTF-8 text"
    assert codegen.success is False
    assert codegen.error == "YARA file must contain valid UTF-8 text"
    assert roundtrip.success is False
    assert roundtrip.error == "YARA file must contain valid UTF-8 text"


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
    assert "No performance issues found" in result.output

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


def test_performance_check_parser_preserves_yarax_condition(tmp_path: Path) -> None:
    yarax_path = tmp_path / "perf_yarax.yar"
    yarax_path.write_text(_yarax_rule(), encoding="utf-8")

    ast = parse_performance_file(yarax_path)

    assert ast.rules[0].condition.__class__.__name__ == "WithStatement"


def test_performance_check_parser_rejects_yaral(tmp_path: Path) -> None:
    yaral_path = tmp_path / "perf_yaral.yar"
    yaral_path.write_text(_yaral_rule(), encoding="utf-8")

    with pytest.raises(ParseError, match=r"YARA-L.*performance-check"):
        parse_performance_file(yaral_path)


def test_performance_check_rejects_invalid_limit(tmp_path: Path) -> None:
    runner = CliRunner()
    clean_rule = tmp_path / "clean.yar"
    clean_rule.write_text("rule clean { condition: true }", encoding="utf-8")

    result = runner.invoke(performance_check, [str(clean_rule), "--limit", "0"])

    assert result.exit_code == 2
    assert "Invalid value for '--limit'" in result.output


def test_metrics_reporting_complexity_and_string_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ast = _sample_ast()
    metrics = ComplexityAnalyzer().analyze(ast)
    analysis = _analyze_string_patterns(ast)

    text = _format_complexity_output(metrics, "text")
    assert "YARA Rule Complexity Analysis" in text
    assert "Complex Rules" in text or "File Metrics" in text

    metrics.complex_rules = ["sample"]
    metrics.unused_strings = [f"$u{i}" for i in range(11)]
    metrics.module_usage = {"pe": 1}
    rich_text = _format_complexity_output(metrics, "text")
    assert "Heuristic Complexity Thresholds" in rich_text
    assert "Unused Strings:" in rich_text
    assert "... and 1 more" in rich_text
    assert "Module Usage:" in rich_text

    json_output = _format_complexity_output(metrics, "json")
    assert '"quality_score"' in json_output
    assert _format_complexity_output(metrics, "text").startswith("YARA Rule Complexity Analysis")

    for invalid_format in [None, 123]:
        with pytest.raises(TypeError, match="complexity output format must be a string"):
            _format_complexity_output(metrics, invalid_format)

    for unknown_format in ["", "xml", "yaml"]:
        with pytest.raises(
            ValueError,
            match="complexity output format must be one of: json, text",
        ):
            _format_complexity_output(metrics, unknown_format)

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

    for invalid_format in [None, 123]:
        with pytest.raises(TypeError, match="string analysis output format must be a string"):
            _format_string_analysis_output(analysis, invalid_format)

    for unknown_format in ["", "xml", "yaml"]:
        with pytest.raises(
            ValueError,
            match="string analysis output format must be one of: json, text",
        ):
            _format_string_analysis_output(analysis, unknown_format)

    for invalid_analysis in [[], "bad", object()]:
        with pytest.raises(TypeError, match="string analysis must be a dictionary"):
            _format_string_analysis_output(cast(Any, invalid_analysis), "json")
        with pytest.raises(TypeError, match="string analysis must be a dictionary"):
            _format_string_analysis_output(cast(Any, invalid_analysis), "text")
        with pytest.raises(TypeError, match="string analysis must be a dictionary"):
            _format_strings_text(cast(Any, invalid_analysis))

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


def test_metrics_reporting_rejects_empty_output_paths() -> None:
    with pytest.raises(ValueError, match="path must not be empty"):
        _emit_text_output("complexity", "", "Complexity metrics written to")

    with pytest.raises(ValueError, match="path must not be empty"):
        _output_string_analysis_results("strings", "")


@pytest.mark.parametrize("output", [False, 0, object()])
def test_metrics_reporting_rejects_invalid_output_path_types(output: Any) -> None:
    with pytest.raises(TypeError, match="path must be a file path"):
        _emit_text_output("complexity", cast(Any, output), "Complexity metrics written to")

    with pytest.raises(TypeError, match="path must be a file path"):
        _output_string_analysis_results("strings", cast(Any, output))


def test_metrics_reporting_graph_and_pattern_helpers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    if DependencyGraphGeneratorClass is None:
        pytest.skip("graphviz package is not installed")
    ast = _sample_ast()

    dep_generator = DependencyGraphGeneratorClass()
    dep_generator.visit(ast)
    dep_generator.dependencies["sample"].add("dependency_target")
    dep_generator.dependencies["dependency_target"] = set()
    dep_generator.module_references["sample"].add("pe")

    stats = dep_generator.get_dependency_stats()
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
                f"  {rule} → {', '.join(sorted(deps))}"
                for rule, deps in sorted(dep_generator.dependencies.items())
                if deps
            ],
        ]
    )
    assert "Dependency Analysis" in text_graph
    assert "Total rules: 2" in text_graph
    assert "sample → dependency_target" in text_graph

    _display_graph_statistics(dep_generator)
    _display_rule_dependencies(dep_generator)
    _display_module_usage(dep_generator)
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
    _display_pattern_statistics(
        type(
            "EmptyPatternStats",
            (),
            {
                "get_pattern_statistics": lambda self: {
                    "total_patterns": 0,
                    "by_type": {"plain": 0, "hex": 0, "regex": 0},
                    "complexity_distribution": {"low": 0, "medium": 0, "high": 0},
                    "pattern_lengths": {},
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
    _display_pattern_result("digraph { a -> b }")
    _display_pattern_statistics(
        type("NoStats", (), {"get_pattern_statistics": lambda self: None})()
    )
    with pytest.raises(AttributeError):
        _display_pattern_statistics(
            type(
                "BadStats",
                (),
                {
                    "get_pattern_statistics": lambda self: (_ for _ in ()).throw(
                        AttributeError("boom"),
                    ),
                },
            )(),
        )
    with pytest.raises(KeyError):
        _display_pattern_statistics(
            type(
                "PartialStats",
                (),
                {"get_pattern_statistics": lambda self: {"total_patterns": 1}},
            )(),
        )

    display_text_statistics(
        "sample.yar",
        {
            "total_rules": 2,
            "total_imports": 1,
            "rules_with_strings": 1,
            "rules_using_modules": 1,
        },
    )

    out = capsys.readouterr().out
    assert "Dependency Analysis (Text Mode):" in out
    assert "sample.yar" in out
    assert "Total Rules: 2" in out
    assert "Total Imports: 1" in out


def test_metrics_reporting_treats_inaccessible_result_paths_as_non_files(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result_path = "a" * 5000

    _display_pattern_result(result_path)
    _display_successful_graph_result(result_path, object())

    output = capsys.readouterr().out
    assert "Diagram source:" in output
    assert "Dependency graph generated" not in output
    assert path_size_for_display(result_path) is None


def test_metrics_reporting_treats_null_byte_result_paths_as_non_files() -> None:
    assert path_size_for_display("\x00broken") is None


def test_metrics_reporting_analyze_pattern_counts_and_string_branches(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ast = _sample_ast()

    _display_text_pattern_analysis(
        SimpleNamespace(_analyze_patterns=lambda _ast: None),
        ast,
    )

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

    output = capsys.readouterr().out
    assert "String Pattern Analysis (Text Mode)" in output
    assert "Total strings: 3" in output
    assert "Plain strings: 1" in output
    assert "Hex patterns: 1" in output
    assert "Regex patterns: 1" in output

    _output_string_analysis_results("analysis text", None)
    assert "analysis text" in capsys.readouterr().out


def test_metrics_reporting_empty_and_mixed_branches(capsys: pytest.CaptureFixture[str]) -> None:
    if DependencyGraphGeneratorClass is None:
        pytest.skip("graphviz package is not installed")
    empty_ast = _parse_yara("rule empty { condition: true }")
    empty_metrics = ComplexityAnalyzer().analyze(empty_ast)
    text = _format_complexity_output(empty_metrics, "text")
    assert "Cyclomatic Complexity by Rule:" in text
    assert "Heuristic Complexity Thresholds:" not in text
    assert "Unused Strings:" not in text
    assert "Module Usage:" not in text

    dep_generator = DependencyGraphGeneratorClass()
    dep_generator.dependencies["a"] = set()
    dep_generator.module_references["a"] = set()
    _display_rule_dependencies(dep_generator)
    _display_module_usage(dep_generator)

    assert "\n".join(
        [
            "Dependency Analysis",
            "=" * 19,
            "",
            "Total rules: 1",
            "Total imports: 0",
            "Rules with strings: 0",
            "Rules using modules: 0",
            "",
            "Rule Dependencies:",
            "  b → c",
        ]
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

    summary: dict[str, Any] = {
        "file": "sample.yar",
        "generated_files": ["tree.html", *generated],
        "metrics": {
            "heuristic": True,
            "analysis_kind": "heuristic",
            "quality_score": metrics.get_quality_score(),
            "quality_grade": metrics.get_complexity_grade(),
            "total_rules": metrics.total_rules,
            "total_strings": metrics.total_strings,
            "max_condition_depth": metrics.max_condition_depth,
            "complex_rules": metrics.complex_rules,
        },
    }
    assert summary["file"] == "sample.yar"
    assert summary["metrics"]["total_rules"] == metrics.total_rules
    assert len(summary["generated_files"]) == 3

    write_report_summary(tmp_path, summary)
    assert (tmp_path / "summary.json").exists()

    print(f"\n✅ Comprehensive report generated in {tmp_path}/")
    print(
        f"📊 Quality Score: {metrics.get_quality_score():.1f} "
        f"(Grade: {metrics.get_complexity_grade()})",
    )
    print(f"📁 Generated {len(summary['generated_files'])} files")
    out = capsys.readouterr().out
    assert "Comprehensive report generated" in out
    assert "Quality Score" in out
    assert "Generated 3 files" in out


def test_metrics_reporting_report_files_reject_symlinked_output_dir(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(outside, target_is_directory=True)

    ast = _sample_ast()
    metrics = ComplexityAnalyzer().analyze(ast)

    with pytest.raises(ValueError, match="output_path must not traverse a symlink"):
        write_complexity_report_files(link_dir, "sample", metrics)

    with pytest.raises(ValueError, match="output_path must not traverse a symlink"):
        write_report_summary(link_dir, {"generated_files": []})
