"""Keep every conditional test skip linked to visible tracking work."""

from __future__ import annotations

import ast
from pathlib import Path

TRACKING_ISSUE = "https://github.com/seifreed/yaraast/issues/24"
SKIP_CALLS = frozenset({"skip", "skipif", "importorskip"})


def test_every_test_skip_links_to_tracking_issue() -> None:
    offenders: list[str] = []
    for path in sorted(Path("tests").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if call_name in SKIP_CALLS and TRACKING_ISSUE not in ast.unparse(node):
                offenders.append(f"{path}:{node.lineno} ({call_name})")

    assert offenders == []
