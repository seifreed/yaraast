"""More tests for libyara services helpers without mocks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

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


@pytest.mark.parametrize("optimize", [None, 1, "yes", object()])
def test_compile_yara_rejects_invalid_optimize_types(optimize: Any) -> None:
    with pytest.raises(TypeError, match="optimize must be a boolean"):
        ls.compile_yara("missing.yar", optimize=cast(bool, optimize), debug=False)


@pytest.mark.parametrize("debug", [None, 1, "yes", object()])
def test_compile_yara_rejects_invalid_debug_types(debug: Any) -> None:
    with pytest.raises(TypeError, match="debug must be a boolean"):
        ls.compile_yara("missing.yar", optimize=False, debug=cast(bool, debug))


@pytest.mark.parametrize("optimize", [None, 1, "yes", object()])
def test_scan_yara_rejects_invalid_optimize_types(optimize: Any) -> None:
    with pytest.raises(TypeError, match="optimize must be a boolean"):
        ls.scan_yara(
            "missing.yar",
            "sample.bin",
            optimize=cast(bool, optimize),
            timeout=1,
            fast=False,
        )


@pytest.mark.parametrize("fast", [None, 1, "yes", object()])
def test_scan_yara_rejects_invalid_fast_types(fast: Any) -> None:
    with pytest.raises(TypeError, match="fast must be a boolean"):
        ls.scan_yara(
            "missing.yar",
            "sample.bin",
            optimize=False,
            timeout=1,
            fast=cast(bool, fast),
        )


@pytest.mark.parametrize("timeout", [True, "1", object()])
def test_scan_yara_rejects_invalid_timeout_types(timeout: Any) -> None:
    with pytest.raises(TypeError, match="timeout must be an integer"):
        ls.scan_yara(
            "missing.yar",
            "sample.bin",
            optimize=False,
            timeout=cast(int, timeout),
            fast=False,
        )


@pytest.mark.parametrize("timeout", [0, -1])
def test_scan_yara_rejects_non_positive_timeouts(timeout: int) -> None:
    with pytest.raises(ValueError, match="timeout must be at least 1"):
        ls.scan_yara(
            "missing.yar",
            "sample.bin",
            optimize=False,
            timeout=timeout,
            fast=False,
        )


def test_scan_yara_rejects_null_byte_target(tmp_path: Path) -> None:
    rule_file = tmp_path / "r.yar"
    rule_file.write_text("rule a { condition: true }", encoding="utf-8")

    if not lib.YARA_AVAILABLE:
        pytest.skip("yara-python is not installed")

    with pytest.raises(ValueError, match="target must not contain null bytes"):
        ls.scan_yara(
            str(rule_file),
            "\x00broken",
            optimize=False,
            timeout=1,
            fast=False,
        )


def test_libyara_services_reject_yarax_only_syntax(tmp_path: Path) -> None:
    if not lib.YARA_AVAILABLE:
        pytest.skip("yara-python is not installed")

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


def test_libyara_services_resolve_relative_includes_from_rules_file(tmp_path: Path) -> None:
    if not lib.YARA_AVAILABLE:
        pytest.skip("yara-python is not installed")

    include_file = tmp_path / "shared.yar"
    include_file.write_text("rule shared_rule { condition: true }\n", encoding="utf-8")
    rule_file = tmp_path / "main.yar"
    rule_file.write_text(
        """
include "shared.yar"

rule main_rule {
    condition:
        shared_rule
}
""".lstrip(),
        encoding="utf-8",
    )
    target_file = tmp_path / "sample.bin"
    target_file.write_bytes(b"")

    compile_result, _compiler, _ast = ls.compile_yara(
        str(rule_file),
        optimize=False,
        debug=False,
    )
    scan_result, _matcher, scan_compile_result = ls.scan_yara(
        str(rule_file),
        str(target_file),
        optimize=False,
        timeout=1,
        fast=False,
    )

    assert compile_result.success is True
    assert scan_compile_result.success is True
    assert scan_result is not None
    assert scan_result["success"] is True
    assert [match["rule"] for match in scan_result["matches"]] == [
        "shared_rule",
        "main_rule",
    ]
