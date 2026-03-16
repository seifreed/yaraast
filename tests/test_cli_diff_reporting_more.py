from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from yaraast.cli import diff_reporting as dr


def _result(**overrides):
    base = {
        "change_summary": {},
        "added_rules": [],
        "removed_rules": [],
        "modified_rules": [],
        "logical_changes": [],
        "structural_changes": [],
        "style_only_changes": [],
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_diff_reporting_headers_summary_and_rule_lists(capsys) -> None:
    dr.display_no_changes(Path("/tmp/a.yar"), Path("/tmp/b.yar"))
    dr.display_diff_header(Path("/tmp/a.yar"), Path("/tmp/b.yar"))
    dr.show_diff_summary(
        _result(change_summary={"added_rules": 1, "removed_rules": 0, "style_changes": 2}),
    )
    dr.show_rule_changes(
        _result(
            added_rules=["a1", "a2"],
            removed_rules=["r1"],
            modified_rules=["m1"],
        ),
    )

    out = capsys.readouterr().out
    assert "No differences found between a.yar and b.yar" in out
    assert "AST Diff: a.yar -> b.yar" in out
    assert "Added Rules (2)" in out
    assert "Removed Rules (1)" in out
    assert "Modified Rules (1)" in out
    assert "Style Changes: 2" in out


def test_diff_reporting_details_style_and_significance(capsys) -> None:
    many_styles = [f"style change {i}" for i in range(12)]
    result = _result(
        logical_changes=["logic 1", "logic 2"],
        structural_changes=["structure 1"],
        style_only_changes=many_styles,
        added_rules=["added"],
        removed_rules=["removed"],
    )
    dr.show_change_details(result, logical_only=False, no_style=False)
    dr.show_change_significance(result)

    style_only = _result(style_only_changes=["indent only", "spacing only"])
    dr.show_change_significance(style_only)

    out = capsys.readouterr().out
    assert "Logical Changes (2)" in out
    assert "Structural Changes (1)" in out
    assert "Style-Only Changes (12)" in out
    assert "... and 2 more style changes" in out
    assert "logical changes that affect rule behavior" in out
    assert "only 2 style changes" in out


def test_diff_reporting_respects_logical_only_and_no_style_flags(capsys) -> None:
    result = _result(
        logical_changes=[],
        structural_changes=[],
        style_only_changes=["style 1"],
    )
    dr.show_change_details(result, logical_only=True, no_style=False)
    dr.show_change_details(result, logical_only=False, no_style=True)
    out = capsys.readouterr().out
    assert "Style-Only Changes" not in out
