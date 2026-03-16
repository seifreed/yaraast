"""More CLI tests for roundtrip commands (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.roundtrip import roundtrip


def _simple_rule() -> str:
    return """
rule sample_roundtrip {
    strings:
        $a = "abc"
    condition:
        $a
}
"""


def _sample_rule() -> str:
    return """
import "pe"

rule sample_roundtrip : tag1 {
    meta:
        author = "me"
    strings:
        $a = "abc"
    condition:
        $a and pe.number_of_sections > 0
}
"""


def test_roundtrip_test_and_pretty(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_simple_rule().strip(), encoding="utf-8")

    report_path = tmp_path / "roundtrip_report.json"
    result = runner.invoke(
        roundtrip,
        ["test", str(yara_path), "--format", "json", "--verbose", "-o", str(report_path)],
    )
    assert result.exit_code == 0
    assert "Round-trip test PASSED" in result.output
    assert report_path.exists()

    pretty_path = tmp_path / "pretty.yar"
    result = runner.invoke(
        roundtrip,
        [
            "pretty",
            str(yara_path),
            "--style",
            "compact",
            "--indent-size",
            "2",
            "--max-line-length",
            "80",
            "--no-align-meta",
            "--no-align-strings",
            "--preserve-import-order",
            "--preserve-tag-order",
            "-o",
            str(pretty_path),
        ],
    )
    assert result.exit_code == 0
    assert pretty_path.exists()
    assert "Pretty printed" in result.output


def test_roundtrip_pipeline_with_manifest(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule().strip(), encoding="utf-8")

    pipeline_path = tmp_path / "pipeline.yaml"
    pipeline_info = json.dumps({"branch": "main", "commit": "abc123"})
    result = runner.invoke(
        roundtrip,
        [
            "pipeline",
            str(yara_path),
            "--pipeline-info",
            pipeline_info,
            "--include-manifest",
            "-o",
            str(pipeline_path),
        ],
    )

    assert result.exit_code == 0
    assert pipeline_path.exists()
    manifest_path = pipeline_path.with_suffix(".manifest.yaml")
    assert manifest_path.exists()


def test_roundtrip_serialize_deserialize_stdout(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample_stdout.yar"
    yara_path.write_text(_simple_rule().strip(), encoding="utf-8")

    result = runner.invoke(roundtrip, ["serialize", str(yara_path), "--format", "json"])
    assert result.exit_code == 0
    assert result.output.strip().startswith("{")

    # Use serialized JSON from stdout
    json_path = tmp_path / "from_stdout.json"
    json_path.write_text(result.output, encoding="utf-8")

    result = runner.invoke(roundtrip, ["deserialize", str(json_path), "--format", "json"])
    assert result.exit_code == 0
    assert "rule sample_roundtrip" in result.output


def test_roundtrip_pipeline_stdout_no_manifest(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample_pipeline.yar"
    yara_path.write_text(_sample_rule().strip(), encoding="utf-8")

    result = runner.invoke(roundtrip, ["pipeline", str(yara_path)])
    assert result.exit_code == 0
    assert "Statistics:" in result.output
