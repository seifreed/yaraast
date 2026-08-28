"""Fingerprint baselines for incremental diagnostic adoption."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import json
from pathlib import Path
from typing import cast

from yaraast.diagnostics import Diagnostic, DiagnosticResult


@dataclass(frozen=True)
class Baseline:
    """Set of diagnostics accepted by a previous check."""

    fingerprints: frozenset[str]

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        """Load and validate a baseline JSON file."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid baseline file: {path}") from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise ValueError("baseline schema_version must be 1")
        items = data.get("diagnostics")
        if not isinstance(items, list):
            raise ValueError("baseline diagnostics must be an array")
        fingerprints = frozenset(_fingerprint(item) for item in items)
        return cls(fingerprints)

    @classmethod
    def from_result(cls, result: DiagnosticResult) -> Baseline:
        """Create a baseline containing every result diagnostic."""
        return cls(frozenset(item.fingerprint for item in result.diagnostics))

    def filter(self, result: DiagnosticResult) -> DiagnosticResult:
        """Remove diagnostics already present in this baseline."""
        return DiagnosticResult(
            tuple(item for item in result.diagnostics if item.fingerprint not in self.fingerprints)
        )

    def write(self, path: str | Path, diagnostics: Iterable[Diagnostic]) -> None:
        """Write a deterministic baseline JSON file."""
        items = sorted(
            (
                {
                    "diagnostic_id": item.diagnostic_id,
                    "fingerprint": item.fingerprint,
                    "rule_name": item.rule_name,
                    "source_path": item.source_path,
                }
                for item in diagnostics
            ),
            key=lambda item: item["fingerprint"] or "",
        )
        Path(path).write_text(
            json.dumps({"schema_version": 1, "diagnostics": items}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _fingerprint(value: object) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("fingerprint"), str):
        raise ValueError("baseline diagnostics must contain string fingerprints")
    return cast(str, value["fingerprint"])
