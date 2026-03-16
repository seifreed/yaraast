"""More tests for YARA-X reporting helpers (no mocks)."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.cli import yarax_reporting as yr


def test_yarax_reporting_features_and_issues(capsys) -> None:
    yr.display_yarax_features(["with", "lambda"])
    out = capsys.readouterr().out
    assert "YARA-X Features Used" in out
    assert "with" in out and "lambda" in out

    yr.display_yarax_features([])
    out2 = capsys.readouterr().out
    assert "No YARA-X specific features detected" in out2

    issues = [
        SimpleNamespace(severity="error", message="bad1", suggestion="fix1"),
        SimpleNamespace(severity="warning", message="warn1", suggestion=None),
        SimpleNamespace(severity="info", message="info1", suggestion="hint1"),
    ]
    yr.display_compatibility_issues(issues, show_fixes=True)
    captured = capsys.readouterr()
    assert "Errors:" in captured.err
    assert "Warnings:" in captured.out
    assert "Infos:" in captured.out
    assert "fix1" in captured.out


def test_yarax_reporting_showcase_and_playground(capsys) -> None:
    yr.display_feature_showcase()
    showcase = capsys.readouterr().out
    assert "WITH STATEMENTS" in showcase
    assert "PATTERN MATCHING" in showcase
    assert "fully supported" in showcase

    yr.display_playground_input("rule x { condition: true }", used_default=True)
    yr.display_playground_results("rule x { condition: true }", ["with", "slice"])
    out = capsys.readouterr().out
    assert "Example YARA-X code" in out
    assert "Successfully parsed" in out
    assert "Features used: with, slice" in out

    yr.display_playground_input("code", used_default=False)
    out2 = capsys.readouterr().out
    assert "Example YARA-X code" not in out2
