"""Regression tests for compatibility target profiles."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.check import check_path
from yaraast.conformance.engines import YaraXEngine
from yaraast.project_config import ProjectConfig
from yaraast.targets import get_target_profile


def test_builtin_target_profiles_expose_expected_capabilities() -> None:
    livehunt = get_target_profile("virustotal-livehunt")

    assert livehunt.allowed_modules == frozenset({"vt"})
    assert livehunt.supports_includes is False
    assert livehunt.maximum_ruleset_bytes == 1_000_000


def test_unknown_target_is_a_stable_diagnostic(tmp_path: Path) -> None:
    (tmp_path / "sample.yar").write_text("rule sample { condition: true }\n", encoding="utf-8")
    config = ProjectConfig(tmp_path)

    result = check_path(tmp_path, config, targets=("missing-target",), compile_targets=False)

    assert any(item.diagnostic_id == "YARA402" for item in result.diagnostics)


def test_livehunt_rejects_includes(tmp_path: Path) -> None:
    (tmp_path / "sample.yar").write_text(
        'include "common.yar"\nrule sample { condition: true }\n', encoding="utf-8"
    )
    config = ProjectConfig(tmp_path)

    result = check_path(tmp_path, config, targets=("virustotal-livehunt",), compile_targets=False)

    assert any(item.diagnostic_id == "YARA401" for item in result.diagnostics)


@pytest.mark.skipif(
    not YaraXEngine().available,
    reason="yara-x not installed; docs/test-skips.yml",
)
def test_yarax_target_compiles_rule(tmp_path: Path) -> None:
    (tmp_path / "sample.yar").write_text("rule sample { condition: true }\n", encoding="utf-8")
    config = ProjectConfig(tmp_path)

    result = check_path(tmp_path, config, targets=("yara-x-1.20.0",))

    assert not any(item.diagnostic_id == "YARA402" for item in result.diagnostics)


def test_unknown_target_lookup_rejects_empty_name() -> None:
    with pytest.raises(ValueError, match="unknown target"):
        get_target_profile("")
