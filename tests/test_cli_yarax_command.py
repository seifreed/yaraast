"""CLI tests for YARA-X commands."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.yarax import yarax


def _write_yarax(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")
    return str(path)


def test_yarax_parse_show_features(tmp_path) -> None:
    yarax_code = """
    rule yarax_demo {
        strings:
            $a = "test"

        condition:
            with $b = 1:
                $a and $b == 1
    }
    """
    yarax_path = _write_yarax(tmp_path, "demo.yarax", yarax_code)

    runner = CliRunner()
    result = runner.invoke(
        yarax,
        ["parse", yarax_path, "--show-features"],
    )
    assert result.exit_code == 0
    assert "YARA-X Features Used" in result.output
    assert "with statements" in result.output


def test_yarax_check_and_convert(tmp_path) -> None:
    yara_code = """
    rule basic_rule {
        condition:
            true
    }
    """
    yara_path = _write_yarax(tmp_path, "basic.yar", yara_code)

    runner = CliRunner()
    result = runner.invoke(
        yarax,
        ["check", yara_path],
    )
    assert result.exit_code == 0
    assert "compatible" in result.output

    output_path = tmp_path / "converted.yarax"
    result = runner.invoke(
        yarax,
        ["convert", yara_path, "--target", "yarax", "--output", str(output_path)],
    )
    assert result.exit_code == 0
    assert "Converted to YARA-X format" in result.output
    assert output_path.exists()


def test_yarax_features_and_playground() -> None:
    runner = CliRunner()

    result = runner.invoke(yarax, ["features"])
    assert result.exit_code == 0
    assert "YARA-X New Features" in result.output

    result = runner.invoke(yarax, ["playground", "rule r { condition: true }"])
    assert result.exit_code == 0
    assert "Successfully parsed" in result.output
