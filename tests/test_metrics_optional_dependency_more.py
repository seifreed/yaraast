from __future__ import annotations

from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_import_probe(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_metrics_import_degrades_without_graphviz_package() -> None:
    result = _run_import_probe(
        """
import builtins

real_import = builtins.__import__

def import_without_graphviz(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "graphviz":
        raise ModuleNotFoundError("No module named 'graphviz'", name="graphviz")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = import_without_graphviz

from yaraast import metrics

assert metrics.DependencyGraphGenerator is None
assert metrics.ComplexityAnalyzer().__class__.__name__ == "ComplexityAnalyzer"
""",
    )

    assert result.returncode == 0, result.stderr


def test_metrics_import_propagates_internal_dependency_graph_errors() -> None:
    result = _run_import_probe(
        """
import builtins

real_import = builtins.__import__

def import_with_broken_dependency_graph(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "yaraast.metrics.dependency_graph":
        raise ModuleNotFoundError(
            "broken dependency graph internals",
            name="yaraast.metrics.dependency_graph_generation",
        )
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = import_with_broken_dependency_graph

try:
    import yaraast.metrics
except ModuleNotFoundError as exc:
    assert exc.name == "yaraast.metrics.dependency_graph_generation"
else:
    raise AssertionError("internal metrics import errors must not be hidden")
""",
    )

    assert result.returncode == 0, result.stderr
