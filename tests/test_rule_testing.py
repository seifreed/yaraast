"""Regression tests for local rule test manifests."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.conformance.engines import YaraXEngine
from yaraast.rule_testing import RuleTestManifest, discover_manifests, run_manifests


def test_manifest_loads_schema_and_fixture_cases(tmp_path: Path) -> None:
    path = tmp_path / "test.yml"
    path.write_text(
        """
schema: yaraast-test/v1
rule_id: sample
engines: [yara-x]
positive:
  - path: positives/a.bin
    expected: [sample]
negative:
  - path: negatives/a.bin
    expected: []
budgets:
  max_scan_ms: 100
""",
        encoding="utf-8",
    )

    manifest = RuleTestManifest.load(path)

    assert manifest.rule_id == "sample"
    assert manifest.positive[0].expected == ("sample",)
    assert discover_manifests(tmp_path) == (path,)


@pytest.mark.skipif(
    not YaraXEngine().available,
    reason="yara-x not installed; docs/test-skips.yml",
)
def test_manifest_runs_positive_and_negative_fixtures(tmp_path: Path) -> None:
    manifest_path = tmp_path / "test.yml"
    (tmp_path / "positives").mkdir()
    (tmp_path / "negatives").mkdir()
    (tmp_path / "positives/a.bin").write_bytes(b"hello")
    (tmp_path / "negatives/a.bin").write_bytes(b"goodbye")
    manifest_path.write_text(
        """
schema: yaraast-test/v1
rule_id: sample
engines: [yara-x]
positive:
  - path: positives/a.bin
    expected: [sample]
negative:
  - path: negatives/a.bin
    expected: []
""",
        encoding="utf-8",
    )

    result = run_manifests(
        (RuleTestManifest.load(manifest_path),),
        {"sample": 'rule sample { strings: $a = "hello" condition: $a }'},
    )

    assert not result.failed
    assert result.coverage() == {"rules": 1, "positive": 1, "negative": 1}


def test_manifest_rejects_wrong_schema(tmp_path: Path) -> None:
    path = tmp_path / "test.yml"
    path.write_text("schema: wrong\nrule_id: sample\n", encoding="utf-8")

    with pytest.raises(ValueError, match="schema"):
        RuleTestManifest.load(path)
