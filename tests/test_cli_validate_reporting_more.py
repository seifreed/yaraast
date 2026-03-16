"""Additional coverage for validate reporting helpers."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.cli import validate_reporting as vr


def _result(valid: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        valid=valid,
        rules_tested=3,
        rules_matched=2,
        match_rate=66.6,
        rules_differ=["r1"],
        errors=["e1"],
        yaraast_time=0.1,
        libyara_compile_time=0.2,
        libyara_scan_time=0.3,
        total_time=0.6,
        equivalent=valid,
        ast_equivalent=True,
        code_equivalent=False,
        original_compiles=True,
        regenerated_compiles=False,
        scan_equivalent=True,
        eval_equivalent=False,
        ast_differences=["a"],
        compilation_errors=["c"],
        scan_differences=["s"],
        eval_differences=["v"],
        original_code="rule a { condition: true }",
        regenerated_code="rule a { condition: false }",
    )


def test_display_cross_results_branches(capsys) -> None:
    vr.display_cross_results(_result(valid=True), verbose=False)
    out = capsys.readouterr().out
    assert "Validation PASSED" in out

    vr.display_cross_results(_result(valid=False), verbose=False)
    out2 = capsys.readouterr().out
    assert "Validation FAILED" in out2
    assert "Differences found" in out2
    assert "Performance" in out2

    vr.display_cross_results(_result(valid=True), verbose=True)
    out3 = capsys.readouterr().out
    assert "Rules tested" in out3


def test_roundtrip_reporting_and_details(capsys) -> None:
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


def test_simple_validate_reporters(capsys) -> None:
    vr.display_rule_file_valid(1, 2, 3)
    out = capsys.readouterr().out
    assert "Valid YARA file" in out

    vr.display_rule_file_invalid(RuntimeError("bad"))
    err = capsys.readouterr().err
    assert "Invalid YARA file" in err

    vr.display_external_parse_error(ValueError("oops"))
    err2 = capsys.readouterr().err
    assert "Use format: key=value" in err2

    vr.display_differences("None", [])
    out2 = capsys.readouterr().out
    assert out2 == ""

    vr.display_differences("Some", ["x"])
    out3 = capsys.readouterr().out
    assert "Some:" in out3
