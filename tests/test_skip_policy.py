"""Keep every conditional test skip linked to the documented skip registry."""

from __future__ import annotations

import ast
from pathlib import Path

SKIP_REGISTRY = "docs/test-skips.yml"
SKIP_CALLS = frozenset({"skip", "skipif", "importorskip"})


def test_every_test_skip_links_to_skip_registry() -> None:
    offenders: list[str] = []
    for path in sorted(Path("tests").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if call_name in SKIP_CALLS and SKIP_REGISTRY not in ast.unparse(node):
                offenders.append(f"{path}:{node.lineno} ({call_name})")

    assert offenders == []
