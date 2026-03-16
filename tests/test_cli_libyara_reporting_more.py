"""More tests for libyara reporting helpers (no mocks)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from rich.console import Console

from yaraast.cli import libyara_reporting as lr


def _console() -> Console:
    return Console(record=True, width=120)


def test_libyara_reporting_display_paths() -> None:
    c = _console()

    lr.display_missing_yara(c)
    lr.display_compilation_errors(c, ["e1", "e2"])
    lr.display_compilation_success(c)

    result = SimpleNamespace(
        optimization_stats=SimpleNamespace(
            rules_optimized=1,
            strings_optimized=2,
            conditions_simplified=3,
            constant_folded=4,
        ),
        compilation_time=0.1234,
        ast_node_count=77,
    )
    compiler = SimpleNamespace(
        get_compilation_stats=lambda: {"total_compilations": 5, "successful_compilations": 4}
    )
    lr.display_optimization_stats(c, result)
    lr.display_compilation_stats(c, result, compiler)
    lr.display_compiled_rules_saved(c, "out.yc")
    lr.display_generated_source_preview(c, "A" * 250)

    scan = {"scan_time": 0.2, "data_size": 12, "ast_enhanced": True, "rule_count": 2}
    lr.display_scan_failure(c, {"error": "boom"})
    lr.display_scan_summary(c, scan, [{"rule": "r1"}])

    lr.display_matches(c, [])
    lr.display_matches(
        c,
        [
            {
                "rule": "r1",
                "tags": ["t1", "t2"],
                "strings": ["$a"],
                "ast_context": {"condition_complexity": "medium"},
            },
        ],
    )

    lr.display_optimization_hints(c, {"optimization_hints": ["h1", "h2"]})
    lr.display_optimization_hints(c, {})

    matcher = SimpleNamespace(
        get_scan_stats=lambda: {"total_scans": 10, "success_rate": 0.9, "average_scan_time": 0.01}
    )
    lr.display_scan_stats(c, matcher)
    lr.display_scan_stats(c, None)

    optimizer = SimpleNamespace(
        stats=SimpleNamespace(
            rules_optimized=3,
            strings_optimized=4,
            conditions_simplified=5,
            constant_folded=6,
        ),
        optimizations_applied=["opt1", "opt2"],
    )
    lr.display_optimize_results(
        c, optimizer, show_optimizations=True, optimized_code="rule a { condition: true }"
    )

    out = c.export_text()
    assert "yara-python is not installed" in out
    assert "Compilation failed" in out
    assert "Compilation successful" in out
    assert "Optimizations applied:" in out
    assert "Compilation Stats:" in out
    assert "Scan failed: boom" in out
    assert "Matches found: 1" in out
    assert "Tags: t1, t2" in out
    assert "Optimization Hints:" in out
    assert "Scan Statistics:" in out
    assert "Optimization completed" in out


def test_libyara_error_handler_paths() -> None:
    c = _console()

    with pytest.raises(lr.LibYaraCommandError):
        lr.handle_libyara_error(c, RuntimeError("yara-python is not installed"))

    with pytest.raises(lr.LibYaraCommandError):
        lr.handle_libyara_error(c, RuntimeError("runtime explode"))

    with pytest.raises(lr.LibYaraCommandError):
        lr.handle_libyara_error(c, ImportError("bad import"))

    with pytest.raises(lr.LibYaraCommandError):
        lr.handle_libyara_error(c, ValueError("<unsafe>"))

    out = c.export_text()
    assert "Install with: pip install yara-python" in out
    assert "runtime explode" in out
    assert "Import error: bad import" in out
    assert "Error: <unsafe>" in out
