"""Real integration tests for yarax/yaral/analyze CLI commands."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.analyze import analyze
from yaraast.cli.commands.yaral import yaral
from yaraast.cli.commands.yarax import yarax


def _write(tmp_path: Path, name: str, content: str) -> str:
    p = tmp_path / name
    p.write_text(dedent(content), encoding="utf-8")
    return str(p)


def _sample_yara() -> str:
    return """
    rule sample {
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


def _sample_yaral() -> str:
    return """
    rule login_attempts {
        meta:
            author = "unit"
        events:
            $e.metadata.event_type = "USER_LOGIN"
        condition:
            $e
    }
    """


def _invalid_rule() -> str:
    return "rule broken { condition: "


def test_yarax_real_paths(tmp_path: Path) -> None:
    runner = CliRunner()

    yarax_file = _write(tmp_path, "ok.yarax", _sample_yarax())
    yara_file = _write(tmp_path, "ok.yar", _sample_yara())
    bad_file = _write(tmp_path, "bad.yarax", _invalid_rule())

    out_ast = tmp_path / "ast.txt"
    parse_ok = runner.invoke(yarax, ["parse", yarax_file, "-o", str(out_ast), "--show-features"])
    assert parse_ok.exit_code == 0
    assert out_ast.exists()
    assert "YARA-X Features Used" in parse_ok.output

    parse_bad = runner.invoke(yarax, ["parse", bad_file])
    assert parse_bad.exit_code != 0

    check_ok = runner.invoke(yarax, ["check", yara_file])
    assert check_ok.exit_code == 0

    check_bad = runner.invoke(yarax, ["check", bad_file, "--strict"])
    assert check_bad.exit_code != 0

    out_yarax = tmp_path / "conv.yarax"
    conv_to_yarax = runner.invoke(
        yarax, ["convert", yara_file, "--target", "yarax", "-o", str(out_yarax)]
    )
    assert conv_to_yarax.exit_code == 0
    assert out_yarax.exists()

    conv_to_yarax_stdout = runner.invoke(yarax, ["convert", yara_file, "--target", "yarax"])
    assert conv_to_yarax_stdout.exit_code == 0
    assert "rule" in conv_to_yarax_stdout.output.lower()

    conv_bad = runner.invoke(yarax, ["convert", bad_file, "--target", "yara"])
    assert conv_bad.exit_code != 0

    playground_file = runner.invoke(yarax, ["playground", "--file", yarax_file])
    assert playground_file.exit_code == 0
    assert "Successfully parsed" in playground_file.output

    playground_default = runner.invoke(yarax, ["playground"])
    assert playground_default.exit_code == 0
    assert "Example YARA-X code" in playground_default.output

    playground_bad = runner.invoke(yarax, ["playground", _invalid_rule()])
    assert playground_bad.exit_code == 0
    assert "Parse error" in playground_bad.output


def test_yaral_real_paths(tmp_path: Path) -> None:
    runner = CliRunner()

    good = _write(tmp_path, "ok.yaral", _sample_yaral())
    other = _write(
        tmp_path, "other.yaral", _sample_yaral().replace("login_attempts", "login_attempts_2")
    )
    bad = _write(tmp_path, "bad.yaral", _invalid_rule())
    bad_path = str(tmp_path)  # directory path triggers read error in command handlers

    parse_yaml = runner.invoke(yaral, ["parse", good, "--format", "yaml"])
    assert parse_yaml.exit_code == 0

    parse_text = runner.invoke(yaral, ["parse", good, "--format", "text"])
    assert parse_text.exit_code == 0

    parse_bad = runner.invoke(yaral, ["parse", bad])
    assert parse_bad.exit_code != 0

    validate_ok = runner.invoke(yaral, ["validate", good, "--json", "--strict"])
    assert validate_ok.exit_code == 0

    validate_bad = runner.invoke(yaral, ["validate", bad])
    assert validate_bad.exit_code != 0

    optimize_dry = runner.invoke(yaral, ["optimize", good, "--dry-run"])
    assert optimize_dry.exit_code == 0

    out_opt = tmp_path / "opt.yaral"
    optimize_stats = runner.invoke(yaral, ["optimize", good, "--stats", "-o", str(out_opt)])
    assert optimize_stats.exit_code == 0
    assert out_opt.exists()

    optimize_bad = runner.invoke(yaral, ["optimize", bad])
    assert optimize_bad.exit_code != 0

    generate_ok = runner.invoke(yaral, ["generate", good, "--format"])
    assert generate_ok.exit_code == 0

    generate_bad = runner.invoke(yaral, ["generate", bad_path])
    assert generate_bad.exit_code != 0

    compare_sem = runner.invoke(yaral, ["compare", good, good, "--semantic"])
    assert compare_sem.exit_code == 0

    compare_struct = runner.invoke(yaral, ["compare", good, other])
    assert compare_struct.exit_code == 0

    compare_bad = runner.invoke(yaral, ["compare", good, bad_path])
    assert compare_bad.exit_code != 0

    info = runner.invoke(yaral, ["info", "--examples", "--fields", "--functions"])
    assert info.exit_code == 0


def test_analyze_real_paths(tmp_path: Path) -> None:
    runner = CliRunner()

    good = _write(tmp_path, "ok.yar", _sample_yara())
    bad = _write(tmp_path, "bad.yar", _invalid_rule())

    full_json = runner.invoke(analyze, ["full", good, "--format", "json"])
    assert full_json.exit_code == 0
    assert '"best_practices"' in full_json.output
    assert '"optimization"' in full_json.output

    full_text = runner.invoke(analyze, ["full", good])
    assert full_text.exit_code == 0

    out_json = tmp_path / "analysis.json"
    full_json_out = runner.invoke(analyze, ["full", good, "--format", "json", "-o", str(out_json)])
    assert full_json_out.exit_code == 0
    assert out_json.exists()

    full_bad = runner.invoke(analyze, ["full", bad])
    assert full_bad.exit_code != 0

    bp_ok = runner.invoke(analyze, ["best-practices", good, "--category", "all"])
    assert bp_ok.exit_code == 0

    bp_bad = runner.invoke(analyze, ["best-practices", bad])
    assert bp_bad.exit_code != 0

    opt_text = runner.invoke(analyze, ["optimize", good])
    assert opt_text.exit_code == 0

    opt_json = runner.invoke(analyze, ["optimize", good, "--format", "json"])
    assert opt_json.exit_code == 0
    assert '"statistics"' in opt_json.output
    assert '"suggestions"' in opt_json.output

    opt_out = tmp_path / "opt-analysis.json"
    opt_json_out = runner.invoke(
        analyze, ["optimize", good, "--format", "json", "-o", str(opt_out)]
    )
    assert opt_json_out.exit_code == 0
    assert opt_out.exists()

    opt_bad = runner.invoke(analyze, ["optimize", bad])
    assert opt_bad.exit_code != 0
