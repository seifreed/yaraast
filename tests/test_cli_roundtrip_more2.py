from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.roundtrip import roundtrip


def _good_rule() -> str:
    return """
// comment that tends to stress roundtrip formatting
rule sample_roundtrip {
    strings:
        $a = "abc"
    condition:
        $a
}
"""


def _bad_rule() -> str:
    return "rule broken { condition: }"


def test_roundtrip_commands_error_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    bad_yara = tmp_path / "bad.yar"
    bad_json = tmp_path / "bad.json"
    bad_yara.write_text(_bad_rule(), encoding="utf-8")
    bad_json.write_text("{bad json", encoding="utf-8")

    for subcommand, expected in [
        (["serialize", str(bad_yara)], "Error serializing"),
        (["test", str(bad_yara)], "Error testing"),
        (["pretty", str(bad_yara)], "Error pretty printing"),
        (["pipeline", str(bad_yara)], "Error creating pipeline YAML"),
        (["deserialize", str(bad_json), "--format", "json"], "Error deserializing"),
    ]:
        result = runner.invoke(roundtrip, subcommand)
        assert result.exit_code != 0
        assert expected in result.output


def test_roundtrip_pipeline_include_manifest_without_output(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_good_rule().strip(), encoding="utf-8")

    result = runner.invoke(roundtrip, ["pipeline", str(yara_path), "--include-manifest"])

    assert result.exit_code == 0
    assert "Statistics:" in result.output
    assert not list(tmp_path.glob("*.manifest.yaml"))


def test_roundtrip_test_writes_detailed_results_on_success(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    out_path = tmp_path / "results.json"
    yara_path.write_text(
        """
rule sample_roundtrip {
    condition:
        true
}
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(
        roundtrip,
        ["test", str(yara_path), "--format", "json", "-o", str(out_path)],
    )

    assert result.exit_code == 0
    assert out_path.exists()
    assert "Detailed results saved to" in result.output


def test_roundtrip_test_failure_path_with_saved_results(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "commented.yar"
    out_path = tmp_path / "failed_results.json"
    yara_path.write_text(_good_rule().strip(), encoding="utf-8")

    result = runner.invoke(
        roundtrip,
        ["test", str(yara_path), "--format", "json", "--verbose", "-o", str(out_path)],
    )

    assert result.exit_code != 0
    assert "Round-trip test FAILED" in result.output
    assert "Detailed results saved to" in result.output
    assert out_path.exists()


def test_roundtrip_serialize_and_pretty_stdout_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_good_rule().strip(), encoding="utf-8")

    serialize_result = runner.invoke(
        roundtrip,
        ["serialize", str(yara_path), "--format", "yaml", "--no-comments", "--no-formatting"],
    )
    assert serialize_result.exit_code == 0
    assert "roundtrip_metadata" in serialize_result.output

    pretty_result = runner.invoke(
        roundtrip,
        [
            "pretty",
            str(yara_path),
            "--style",
            "verbose",
            "--preserve-import-order",
            "--preserve-tag-order",
        ],
    )
    assert pretty_result.exit_code == 0
    assert "rule sample_roundtrip" in pretty_result.output
