"""Additional real CLI tests for YARA-L (no mocks)."""

from __future__ import annotations

import json
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.yaral import yaral


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def _sample_rule() -> str:
    return """
    rule login_attempts {
        meta:
            author = "unit"
            description = "test rule"
            severity = "low"

        events:
            $e.metadata.event_type = "USER_LOGIN"

        condition:
            $e
    }
    """


def test_yaral_parse_json(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yaral", _sample_rule())
    runner = CliRunner()

    result = runner.invoke(yaral, ["parse", file_path, "--format", "json"])

    assert result.exit_code == 0
    assert "Successfully parsed" in result.output


def test_yaral_validate_json_strict(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yaral", _sample_rule())
    runner = CliRunner()

    result = runner.invoke(yaral, ["validate", file_path, "--json", "--strict"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["errors"] == []


def test_yaral_generate_format_and_optimize(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yaral", _sample_rule())
    runner = CliRunner()

    gen = runner.invoke(yaral, ["generate", file_path, "--format"])
    assert gen.exit_code == 0
    assert "Successfully generated" in gen.output

    dry = runner.invoke(yaral, ["optimize", file_path, "--dry-run"])
    assert dry.exit_code == 0
    assert "Optimization Preview" in dry.output


def test_yaral_compare_semantic_and_structural(tmp_path) -> None:
    file_a = _write(tmp_path, "a.yaral", _sample_rule())
    file_b = _write(tmp_path, "b.yaral", _sample_rule())
    file_c = _write(
        tmp_path,
        "c.yaral",
        _sample_rule().replace("login_attempts", "login_attempts_v2"),
    )

    runner = CliRunner()

    semantic = runner.invoke(yaral, ["compare", file_a, file_b, "--semantic"])
    assert semantic.exit_code == 0
    assert "semantically equivalent" in semantic.output

    structural = runner.invoke(yaral, ["compare", file_a, file_c])
    assert structural.exit_code == 0
    assert "differences" in structural.output or "Different number of rules" in structural.output


def test_yaral_info_flags() -> None:
    runner = CliRunner()
    result = runner.invoke(yaral, ["info", "--examples", "--fields", "--functions"])

    assert result.exit_code == 0
    assert "Example YARA-L Rules" in result.output
    assert "Valid UDM Field Namespaces" in result.output
    assert "Available Aggregation Functions" in result.output
