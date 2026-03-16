"""More tests for serialize display services (no mocks)."""

from __future__ import annotations

from types import SimpleNamespace

from rich.console import Console

from yaraast.cli import serialize_display_services as sds
from yaraast.serialization import DiffType


def test_display_protobuf_stats_and_diff_tables() -> None:
    console = Console(record=True, width=120)
    orig_console = sds.console
    sds.console = console
    try:
        sds._display_protobuf_stats(
            {
                "binary_size_bytes": 1024,
                "text_size_bytes": 2048,
                "compression_ratio": 2.0,
                "rules_count": 3,
                "imports_count": 1,
            }
        )

        diff_result = SimpleNamespace(
            change_summary={"added": 1, "removed": 1, "modified": 1, "moved": 1, "unchanged": 2},
            differences=[
                SimpleNamespace(
                    diff_type=DiffType.ADDED,
                    path="/rules/1",
                    node_type="Rule",
                    old_value=None,
                    new_value="x",
                ),
                SimpleNamespace(
                    diff_type=DiffType.REMOVED,
                    path="/rules/2",
                    node_type="Rule",
                    old_value="x",
                    new_value=None,
                ),
                SimpleNamespace(
                    diff_type=DiffType.MODIFIED,
                    path="/rules/0/condition",
                    node_type="Condition",
                    old_value="true",
                    new_value="false",
                ),
                SimpleNamespace(
                    diff_type=DiffType.MOVED,
                    path="/rules/3",
                    node_type="Rule",
                    old_value="a",
                    new_value="b",
                ),
            ],
            statistics={
                "old_rules_count": 2,
                "new_rules_count": 3,
                "old_imports_count": 0,
                "new_imports_count": 1,
            },
            old_ast_hash="abc",
            new_ast_hash="def",
        )

        sds._display_diff_summary(diff_result)
        sds._display_detailed_changes(diff_result)
        sds._display_diff_statistics(diff_result)

        too_many = SimpleNamespace(differences=[object()] * 21)
        sds._display_detailed_changes(too_many)

        out = console.export_text()
        assert "Protobuf Serialization Stats" in out
        assert "AST Differences Summary" in out
        assert "Detailed Changes" in out
        assert "Old:" in out and "New:" in out
        assert "Comparison Statistics" in out
        assert "save detailed changes" in out
    finally:
        sds.console = orig_console


def test_build_validation_panel_success_and_failure() -> None:
    ast = SimpleNamespace(rules=[1, 2], imports=[1], includes=[])
    ok_panel = sds.build_validation_panel("a.json", "json", ast, None)
    err_panel = sds.build_validation_panel("a.json", "json", None, ValueError("bad"))

    ok_text = str(ok_panel.renderable)
    err_text = str(err_panel.renderable)
    assert "Valid JSON serialization" in ok_text
    assert "Rules: 2" in ok_text
    assert "Invalid JSON serialization" in err_text
    assert "bad" in err_text
