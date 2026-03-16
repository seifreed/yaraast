"""Additional tests for roundtrip reporting helpers."""

from __future__ import annotations

from pathlib import Path

from yaraast.cli import roundtrip_reporting as rr


class _Ast:
    def __init__(self, rules=1, imports=0, includes=0):
        self.rules = [object()] * rules
        self.imports = [object()] * imports
        self.includes = [object()] * includes


def test_display_verbose_source_truncates_both_sections(capsys) -> None:
    result = {
        "original_source": "\n".join(f"orig {i}" for i in range(12)),
        "reconstructed_source": "\n".join(f"new {i}" for i in range(12)),
    }

    rr._display_verbose_source(result)

    out = capsys.readouterr().out
    assert "Original source (12 lines)" in out
    assert "Reconstructed source (12 lines)" in out
    assert out.count("... (truncated)") == 2


def test_display_pipeline_result_manifest_header_without_content(capsys) -> None:
    rr.display_pipeline_result(
        output=None,
        yaml_content="yaml: 1",
        include_manifest=True,
        manifest_content=None,
        ast=_Ast(rules=2, imports=1, includes=1),
    )

    out = capsys.readouterr().out
    assert "yaml: 1" in out
    assert "--- Rules Manifest ---" in out
    assert "Rules: 2" in out
    assert "Imports: 1" in out
    assert "Includes: 1" in out


def test_display_test_failure_non_verbose(capsys) -> None:
    rr._display_test_failure(
        Path("rule.yar"),
        {"differences": ["a", "b"]},
        verbose=False,
    )

    out = capsys.readouterr().out
    assert "Round-trip test FAILED" in out
    assert "Differences found: 2" in out
    assert "Differences:" not in out
