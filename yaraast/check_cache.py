"""Small on-disk cache for repository check results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from yaraast.diagnostics import Diagnostic, DiagnosticResult


class CheckCache:
    """Cache diagnostics by relative source path and content key."""

    def __init__(self, root: str | Path) -> None:
        self.path = Path(root) / ".yaraast" / "check-cache.json"
        self._entries: dict[str, Any] = self._load()

    def get(self, source_path: str, key: str) -> DiagnosticResult | None:
        """Return a cached result when its content key matches."""
        entry = self._entries.get(source_path)
        if not isinstance(entry, dict) or entry.get("key") != key:
            return None
        diagnostics = entry.get("diagnostics")
        if not isinstance(diagnostics, list):
            return None
        try:
            restored = tuple(Diagnostic.from_dict(item) for item in diagnostics)
        except (KeyError, TypeError, ValueError):
            return None
        return DiagnosticResult(restored)

    def put(self, source_path: str, key: str, result: DiagnosticResult) -> None:
        """Store one source result in memory."""
        self._entries[source_path] = {
            "key": key,
            "diagnostics": [diagnostic.to_dict() for diagnostic in result.diagnostics],
        }

    def save(self) -> None:
        """Persist the cache as deterministic JSON."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._entries, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def clear(self) -> None:
        """Remove the cache file if it exists."""
        if self.path.exists():
            self.path.unlink()
        self._entries.clear()

    def info(self) -> dict[str, int | str]:
        """Return cache path and entry count."""
        return {"path": str(self.path), "entries": len(self._entries)}

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}
