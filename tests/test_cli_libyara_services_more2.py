"""More tests for libyara services helpers without mocks."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.cli import libyara_services as ls
import yaraast.libyara as lib


def test_ensure_yara_available_branches() -> None:
    original = lib.YARA_AVAILABLE
    try:
        lib.YARA_AVAILABLE = True
        ls.ensure_yara_available()

        lib.YARA_AVAILABLE = False
        with pytest.raises(RuntimeError, match="yara-python is not installed"):
            ls.ensure_yara_available()
    finally:
        lib.YARA_AVAILABLE = original


def test_libyara_services_reject_yarax_only_syntax(tmp_path: Path) -> None:
    rule_file = tmp_path / "native_yarax.yar"
    rule_file.write_text(
        "rule x { condition: with xs = [1]: match xs { _ => true } }",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        ls.optimize_yara(str(rule_file))

    message = str(exc_info.value)
    assert "Cannot use YARA-X-only syntax with libyara" in message
    assert "with statements" in message
    assert "pattern matching" in message


def test_scan_yara_compile_failure_branch_real(tmp_path: Path) -> None:
    rule_file = tmp_path / "r.yar"
    target_file = tmp_path / "sample.bin"
    # Syntactically valid but semantically invalid (undefined identifier) so parse
    # succeeds and libyara compilation fails on real path.
    rule_file.write_text("rule a { condition: not_defined }", encoding="utf-8")
    target_file.write_bytes(b"abc")

    if not lib.YARA_AVAILABLE:
        pytest.skip("yara-python is not installed")

    scan_result, matcher, compile_result = ls.scan_yara(
        str(rule_file),
        str(target_file),
        optimize=False,
        timeout=1,
        fast=True,
    )

    assert scan_result is None
    assert matcher is None
    assert compile_result.success is False
