"""CLI tests for YARA-L commands."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.yaral import yaral


def _write_yaral(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")
    return str(path)


def test_yaral_parse_validate_and_info(tmp_path) -> None:
    yaral_code = """
    rule login_attempts {
        meta:
            author = "security"

        events:
            $e.metadata.event_type = "LOGIN"

        condition:
            #e > 1
    }
    """
    yaral_path = _write_yaral(tmp_path, "rule.yaral", yaral_code)

    runner = CliRunner()

    result = runner.invoke(
        yaral,
        ["parse", yaral_path, "--format", "json"],
    )
    assert result.exit_code == 0
    assert "Using standard YARA-L parser" in result.output
    assert "Successfully parsed 1 rules" in result.output

    result = runner.invoke(
        yaral,
        ["validate", yaral_path, "--json"],
    )
    assert result.exit_code == 0
    assert '"valid": true' in result.output

    result = runner.invoke(
        yaral,
        ["info", "--functions"],
    )
    assert result.exit_code == 0
    assert "Available Aggregation Functions" in result.output


def test_yaral_optimize_generate_compare(tmp_path) -> None:
    yaral_code = """
    rule download_events {
        events:
            $e.metadata.event_type = "FILE_DOWNLOAD"

        condition:
            #e > 0
    }
    """
    yaral_path = _write_yaral(tmp_path, "download.yaral", yaral_code)

    runner = CliRunner()

    result = runner.invoke(
        yaral,
        ["optimize", yaral_path, "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Optimization Preview" in result.output

    result = runner.invoke(
        yaral,
        ["generate", yaral_path, "--format"],
    )
    assert result.exit_code == 0
    assert "Successfully generated code" in result.output

    other_path = _write_yaral(tmp_path, "download2.yaral", yaral_code)
    result = runner.invoke(
        yaral,
        ["compare", yaral_path, other_path, "--semantic"],
    )
    assert result.exit_code == 0
    assert "semantically equivalent" in result.output


def test_yaral_parse_enhanced_writes_output(tmp_path) -> None:
    yaral_code = """
    rule enhanced_parse {
        events:
            $e.metadata.event_type = "LOGIN"
        condition:
            #e > 0
        outcome:
            $count = count(metadata.event_type)
    }
    """
    yaral_path = _write_yaral(tmp_path, "enhanced.yaral", yaral_code)
    output_path = tmp_path / "ast.json"

    runner = CliRunner()
    result = runner.invoke(
        yaral,
        [
            "parse",
            yaral_path,
            "--enhanced",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Using enhanced YARA-L parser" in result.output
    assert output_path.exists()
    assert "rules" in output_path.read_text(encoding="utf-8")
