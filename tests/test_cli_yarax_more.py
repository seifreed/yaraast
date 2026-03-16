"""Additional real CLI tests for YARA-X (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.yarax import yarax


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def _sample_yara() -> str:
    return """
    rule sample_yara {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """


def _sample_yarax() -> str:
    return """
    rule sample_yarax {
        strings:
            $a = "abc"
        condition:
            with $x = #a:
                $a and $x > 0
    }
    """


def test_yarax_parse_show_features(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yarax", _sample_yarax())
    runner = CliRunner()

    result = runner.invoke(yarax, ["parse", file_path, "--show-features"])

    assert result.exit_code == 0
    assert "YARA-X Features Used" in result.output
    assert "with statements" in result.output


def test_yarax_check_and_convert(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    runner = CliRunner()

    check = runner.invoke(yarax, ["check", file_path])
    assert check.exit_code == 0
    assert "compatible" in check.output

    out_yarax = tmp_path / "out.yarax"
    conv_yarax = runner.invoke(
        yarax, ["convert", file_path, "--target", "yarax", "-o", str(out_yarax)]
    )
    assert conv_yarax.exit_code == 0
    assert out_yarax.exists()

    out_yara = tmp_path / "out.yar"
    conv_yara = runner.invoke(
        yarax, ["convert", str(out_yarax), "--target", "yara", "-o", str(out_yara)]
    )
    assert conv_yara.exit_code == 0
    assert out_yara.exists()


def test_yarax_playground_code_input() -> None:
    runner = CliRunner()
    code = _sample_yarax()

    result = runner.invoke(yarax, ["playground", code])

    assert result.exit_code == 0
    assert "Successfully parsed" in result.output
    assert "Generated code" in result.output
