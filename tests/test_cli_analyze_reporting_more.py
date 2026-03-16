from __future__ import annotations

import pytest

from yaraast.analysis.best_practices import AnalysisReport, Suggestion
from yaraast.analysis.optimization import OptimizationReport, OptimizationSuggestion
from yaraast.cli import analyze_reporting as ar


def test_display_best_practices_report_with_verbose_and_category_filter(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = AnalysisReport(
        suggestions=[
            Suggestion("r1", "style", "error", "bad name", "line 1"),
            Suggestion("r1", "style", "warning", "weak condition", "line 2"),
            Suggestion("r1", "optimization", "info", "consider simplifying", "line 3"),
        ],
        statistics={"rules": 1, "strings": 2},
    )

    with pytest.raises(SystemExit) as exc:
        ar.display_best_practices_report("sample.yar", report, verbose=True, category="style")
    assert exc.value.code == 2

    out = capsys.readouterr().out
    assert "Best Practices Analysis:" in out
    assert "Summary" in out
    assert "Issues:" in out
    assert "Suggestions:" not in out
    assert "Statistics:" in out
    assert "bad name" in out
    assert "weak condition" in out
    assert "consider simplifying" not in out


def test_display_best_practices_report_warning_path_and_success_path(
    capsys: pytest.CaptureFixture[str],
) -> None:
    warn_report = AnalysisReport(
        suggestions=[Suggestion("r1", "style", "warning", "warn only")],
        statistics={},
    )
    with pytest.raises(SystemExit) as exc1:
        ar.display_best_practices_report("warn.yar", warn_report, verbose=False, category="all")
    assert exc1.value.code == 1
    out1 = capsys.readouterr().out
    assert "Use -v to see 0 additional suggestions" in out1

    ok_report = AnalysisReport(
        suggestions=[Suggestion("r2", "style", "info", "looks fine")],
        statistics={},
    )
    with pytest.raises(SystemExit) as exc2:
        ar.display_best_practices_report("ok.yar", ok_report, verbose=True, category="all")
    assert exc2.value.code == 0
    out2 = capsys.readouterr().out
    assert "Suggestions:" in out2
    assert "looks fine" in out2
    assert "No major issues found" in out2


def test_display_summary_issues_and_verbose_info_empty_branches(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ar.display_summary([], [], [])
    ar.display_issues([Suggestion("r", "style", "info", "info only")])
    ar.display_verbose_info([], AnalysisReport(suggestions=[], statistics={}))
    out = capsys.readouterr().out
    assert "Summary" in out
    assert "Errors:" in out
    assert "Warnings:" in out
    assert "Info:" in out
    assert "Issues:" not in out
    assert "Statistics:" not in out


def test_display_optimization_report_and_examples(capsys: pytest.CaptureFixture[str]) -> None:
    report = OptimizationReport(
        suggestions=[
            OptimizationSuggestion("r1", "string", "high issue", "high", "old1", "new1"),
            OptimizationSuggestion("r1", "cond", "medium issue", "medium"),
            OptimizationSuggestion("r1", "minor", "low issue", "low", "old3", "new3"),
        ],
        statistics={},
    )

    ar.display_optimization_report("sample.yar", report, verbose=True)
    out = capsys.readouterr().out
    assert "Optimization Analysis:" in out
    assert "Optimization" in out and "Opportunities" in out
    assert "High" in out and "Medium" in out and "Low" in out
    assert "high issue" in out
    assert "medium issue" in out
    assert "low issue" in out
    assert "Before:" in out
    assert "After:" in out


def test_optimize_display_helpers_skip_empty_levels_and_unknown_style(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = OptimizationReport(
        suggestions=[], statistics={"by_impact": {"high": 0, "medium": 0, "low": 0}}
    )
    ar.optimize_display_impact_summary(report)
    ar.optimize_display_suggestions([], verbose=False)
    ar.display_suggestions_by_level(
        [OptimizationSuggestion("r", "misc", "other issue", "other")],
        "other",
        verbose=False,
    )
    out = capsys.readouterr().out
    assert "Optimization" in out and "Opportunities" in out
    assert "other issue" in out
