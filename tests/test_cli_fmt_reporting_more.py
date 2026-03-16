"""Additional tests for format reporting helpers."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from yaraast.cli import fmt_reporting as fr


def test_display_format_issues_truncates_and_reports_extra_count() -> None:
    console = Console(record=True, width=120)

    fr.display_format_issues(console, [f"issue {i}" for i in range(7)])

    output = console.export_text()
    assert "issue 0" in output
    assert "issue 4" in output
    assert "... and 2 more issues" in output


def test_display_format_diff_handles_no_changes() -> None:
    console = Console(record=True, width=120)

    fr.display_format_diff(
        console,
        Path("sample.yar"),
        "rule a { condition: true }\n",
        "rule a { condition: true }\n\n",
    )

    assert "No formatting changes needed" in console.export_text()


def test_display_format_check_without_issue_details_and_same_file_result() -> None:
    console = Console(record=True, width=120)
    path = Path("sample.yar")

    fr.display_format_check(console, path, True, [])
    fr.display_format_result(console, path, path, "compact")

    output = console.export_text()
    assert "sample.yar needs formatting" in output
    assert "Formatted sample.yar (compact style)" in output


def test_display_format_error_and_diff_fallback_line() -> None:
    console = Console(record=True, width=120)

    fr.display_format_error(console, "boom")
    fr._print_diff_lines(console, [" unchanged line"])

    output = console.export_text()
    assert "boom" in output
    assert "unchanged line" in output
