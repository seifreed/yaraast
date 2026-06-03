"""Additional coverage for validate reporting helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast.cli import validate_reporting as vr


def _result(valid: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        equivalent=valid,
        ast_equivalent=True,
        code_equivalent=False,
        original_compiles=True,
        regenerated_compiles=False,
        scan_equivalent=True,
        ast_differences=["a"],
        compilation_errors=["c"],
        scan_differences=["s"],
        original_code="rule a { condition: true }",
        regenerated_code="rule a { condition: false }",
    )


def test_roundtrip_reporting_and_details(capsys: pytest.CaptureFixture[str]) -> None:
    status_fn = vr.display_roundtrip_summary(_result(valid=False))
    out = capsys.readouterr().out
    assert "Round-trip FAILED" in out
    assert callable(status_fn)

    vr.display_roundtrip_details(_result(valid=False), status_fn, data=b"abc", verbose=False)
    out2 = capsys.readouterr().out
    assert "Scan results match" in out2
    assert "AST differences" in out2

    vr.display_roundtrip_details(_result(valid=True), status_fn, data=None, verbose=True)
    out3 = capsys.readouterr().out
    assert "Original code" in out3


def test_simple_validate_reporters(capsys: pytest.CaptureFixture[str]) -> None:
    vr.display_rule_file_valid(1, 2, 3)
    out = capsys.readouterr().out
    assert "Valid YARA file" in out

    vr.display_rule_file_invalid(RuntimeError("bad"))
    err = capsys.readouterr().err
    assert "Invalid YARA file" in err

    vr.display_differences("None", [])
    out2 = capsys.readouterr().out
    assert out2 == ""

    vr.display_differences("Some", ["x"])
    out3 = capsys.readouterr().out
    assert "Some:" in out3
