"""Regression tests for project configuration and policy loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.diagnostics import Severity
from yaraast.project_config import ProjectConfig


def test_project_config_loads_profiles_and_policies(tmp_path: Path) -> None:
    (tmp_path / "yaraast.toml").write_text(
        """
schema-version = 1
dialect = "yara"
include = ["rules/**/*.yar"]
targets = ["yara-4.5.8"]

[policy]
max-strings-per-rule = 100
max-ruleset-bytes = 1000
forbid-includes = true
require-negative-tests = true
forbid-unused-strings = true

[severity]
YARA103 = "warning"

[quality-gate]
max-warnings = 10

[profile.strict]
extends = "default"
fail-on = "warning"
""",
        encoding="utf-8",
    )

    config = ProjectConfig.load(tmp_path, profile="strict")

    assert config.include == ("rules/**/*.yar",)
    assert config.targets == ("yara-4.5.8",)
    assert config.policy.forbid_unused_strings
    assert config.policy.max_ruleset_bytes == 1000
    assert config.policy.forbid_includes
    assert config.policy.require_negative_tests
    assert config.severity["YARA103"] is Severity.WARNING
    assert config.quality_gate.fail_on is Severity.WARNING


def test_project_config_reads_tool_table_from_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.yaraast]\nschema-version = 1\n",
        encoding="utf-8",
    )

    assert ProjectConfig.load(tmp_path).root == tmp_path


def test_project_config_rejects_profile_cycles(tmp_path: Path) -> None:
    (tmp_path / "yaraast.toml").write_text(
        "[profile.one]\nextends = 'two'\n[profile.two]\nextends = 'one'\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="inheritance cycle"):
        ProjectConfig.load(tmp_path, profile="one")
