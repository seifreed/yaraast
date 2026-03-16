"""Additional tests for metrics_services helpers (no mocks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from yaraast.ast.base import ASTNode
from yaraast.cli import metrics_services as ms
from yaraast.parser import Parser


def _ast() -> ASTNode:
    code = """
rule a { condition: true }
rule b { condition: a }
""".strip()
    return Parser().parse(code)


type CallRecord = tuple[str, str, str] | tuple[str, str, str, str | int]


class _DepGen:
    def __init__(self) -> None:
        self.calls: list[CallRecord] = []

    def generate_graph(
        self,
        ast: ASTNode,
        output_path: str,
        fmt: str,
        engine: str = "dot",
    ) -> str:
        self.calls.append(("full", output_path, fmt, engine))
        return output_path

    def generate_rule_graph(self, ast: ASTNode, output_path: str, fmt: str) -> str:
        self.calls.append(("rules", output_path, fmt))
        return output_path

    def generate_module_graph(self, ast: ASTNode, output_path: str, fmt: str) -> str:
        self.calls.append(("modules", output_path, fmt))
        return output_path

    def generate_complexity_graph(
        self,
        ast: ASTNode,
        cyclo: int,
        output_path: str,
        fmt: str,
    ) -> str:
        self.calls.append(("complexity", output_path, fmt, cyclo))
        return output_path


class _HtmlGen:
    def __init__(self, include_metadata: bool = True) -> None:
        self.include_metadata = include_metadata
        self.calls: list[tuple[str, str, str | None]] = []

    def generate_interactive_html(
        self,
        ast: ASTNode,
        output_path: str,
        title: str | None = None,
    ) -> None:
        self.calls.append(("interactive", output_path, title))
        Path(output_path).write_text("<html>interactive</html>", encoding="utf-8")

    def generate_html(self, ast: ASTNode, output_path: str, title: str | None = None) -> None:
        self.calls.append(("static", output_path, title))
        Path(output_path).write_text("<html>static</html>", encoding="utf-8")


class _PatternGen:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def generate_pattern_flow_diagram(
        self,
        ast: ASTNode,
        output_path: str,
        fmt: str,
    ) -> str:
        self.calls.append(("flow", output_path, fmt))
        return output_path

    def generate_pattern_complexity_diagram(
        self,
        ast: ASTNode,
        output_path: str,
        fmt: str,
    ) -> str:
        self.calls.append(("complexity", output_path, fmt))
        return output_path

    def generate_pattern_similarity_diagram(
        self,
        ast: ASTNode,
        output_path: str,
        fmt: str,
    ) -> str:
        self.calls.append(("similarity", output_path, fmt))
        return output_path

    def generate_hex_pattern_diagram(
        self,
        ast: ASTNode,
        output_path: str,
        fmt: str,
    ) -> str:
        self.calls.append(("hex", output_path, fmt))
        return output_path


def test_metrics_services_path_helpers_and_error_detection() -> None:
    assert (
        ms.determine_graph_output_path("/tmp/rules.yar", None, "full", "svg")
        == "rules_graph_full.svg"
    )
    assert ms.determine_graph_output_path("/tmp/rules.yar", "x.svg", "full", "svg") == "x.svg"

    assert (
        ms.determine_pattern_output_path("/tmp/rules.yar", None, "flow", "dot")
        == "rules_patterns_flow.dot"
    )
    assert ms.determine_pattern_output_path("/tmp/rules.yar", "x.dot", "flow", "dot") == "x.dot"

    assert ms.is_graphviz_error(Exception("ExecutableNotFound")) is True
    assert ms.is_graphviz_error(Exception("failed to execute PosixPath('dot')")) is True
    assert ms.is_graphviz_error(Exception("No such file or directory: PosixPath('dot')")) is True
    assert ms.is_graphviz_error(Exception("another error")) is False


def test_metrics_services_graph_and_pattern_generation_with_generators(tmp_path: Path) -> None:
    ast = _ast()
    dep = _DepGen()

    out, _ = ms.generate_dependency_graph_with_generator(
        dep, ast, "full", str(tmp_path / "f.svg"), "svg", "dot"
    )
    assert out.endswith("f.svg")
    out, _ = ms.generate_dependency_graph_with_generator(
        dep, ast, "rules", str(tmp_path / "r.svg"), "svg", "dot"
    )
    assert out.endswith("r.svg")
    out, _ = ms.generate_dependency_graph_with_generator(
        dep, ast, "modules", str(tmp_path / "m.svg"), "svg", "dot"
    )
    assert out.endswith("m.svg")
    out, _ = ms.generate_dependency_graph_with_generator(
        dep, ast, "complexity", str(tmp_path / "c.svg"), "svg", "dot"
    )
    assert out.endswith("c.svg")

    with pytest.raises(ValueError, match="Unknown graph type"):
        ms.generate_dependency_graph_with_generator(
            dep, ast, "bad", str(tmp_path / "x.svg"), "svg", "dot"
        )

    pat = _PatternGen()
    assert ms.generate_pattern_diagram_with_generator(
        pat, ast, "flow", str(tmp_path / "flow.svg"), "svg"
    ).endswith("flow.svg")
    assert ms.generate_pattern_diagram_with_generator(
        pat, ast, "complexity", str(tmp_path / "cx.svg"), "svg"
    ).endswith("cx.svg")
    assert ms.generate_pattern_diagram_with_generator(
        pat, ast, "similarity", str(tmp_path / "sim.svg"), "svg"
    ).endswith("sim.svg")
    assert ms.generate_pattern_diagram_with_generator(
        pat, ast, "hex", str(tmp_path / "hex.svg"), "svg"
    ).endswith("hex.svg")

    with pytest.raises(ValueError, match="Unknown pattern type"):
        ms.generate_pattern_diagram_with_generator(pat, ast, "bad", str(tmp_path / "z.svg"), "svg")


def test_metrics_services_html_and_wrapper_functions(tmp_path: Path) -> None:
    ast = _ast()

    name_i = ms.generate_html_tree(
        ast,
        tmp_path,
        "rules",
        interactive=True,
        generator_factory=_HtmlGen,
    )
    assert name_i == "rules_tree.html"

    name_s = ms.generate_html_tree(
        ast,
        tmp_path,
        "rules2",
        interactive=False,
        generator_factory=_HtmlGen,
    )
    assert name_s == "rules2_tree.html"

    html_out = ms.generate_html_tree_file(
        ast,
        str(tmp_path / "manual_tree.html"),
        "My Title",
        interactive=False,
        include_metadata=False,
    )
    assert html_out.endswith("manual_tree.html")
    assert (tmp_path / "manual_tree.html").exists()

    html_out_i = ms.generate_html_tree_file(
        ast,
        str(tmp_path / "manual_tree_interactive.html"),
        "My Title I",
        interactive=True,
        include_metadata=True,
    )
    assert html_out_i.endswith("manual_tree_interactive.html")
    assert (tmp_path / "manual_tree_interactive.html").exists()

    dep_files = ms.generate_dependency_graphs(
        ast,
        tmp_path,
        "rules",
        "svg",
        generator_factory=_DepGen,
    )
    assert len(dep_files) == 3

    pat_files = ms.generate_pattern_diagrams(
        ast,
        tmp_path,
        "rules",
        "svg",
        generator_factory=_PatternGen,
    )
    assert len(pat_files) == 3


def test_metrics_services_build_report_and_generator_none(tmp_path: Path) -> None:
    ast = _ast()

    report = ms.build_report(ast, tmp_path, "rules", "svg")
    assert report.base_name == "rules"
    assert "quality_score" in report.complexity_payload
    assert any(name.endswith("_tree.html") for name in report.generated_files)

    orig = ms.DependencyGraphGenerator
    try:
        ms.DependencyGraphGenerator = None
        with pytest.raises(RuntimeError, match="graphviz"):
            ms.generate_dependency_graph(ast, "full", str(tmp_path / "f.svg"), "svg", "dot")
    finally:
        ms.DependencyGraphGenerator = orig

    out = ms.generate_pattern_diagram(ast, "flow", str(tmp_path / "flow_real.svg"), "svg")
    assert out.endswith("flow_real.svg")


def test_metrics_services_error_paths_and_dependency_generator_success(tmp_path: Path) -> None:
    ast = _ast()

    with pytest.raises(RuntimeError, match="graphviz"):
        ms.generate_dependency_graphs(ast, tmp_path, "x", "svg", generator_factory=None)

    original_dep = ms.generate_dependency_graphs
    original_pattern = ms.generate_pattern_diagrams
    try:

        def _raise_dep(*_args: Any, **_kwargs: Any) -> None:
            raise ValueError("dep boom")

        ms.generate_dependency_graphs = _raise_dep
        with pytest.raises(ValueError, match="dep boom"):
            ms.build_report(ast, tmp_path, "x", "svg")

        def _ok_dep(*_args: Any, **_kwargs: Any) -> list[str]:
            return []

        def _raise_pattern(*_args: Any, **_kwargs: Any) -> None:
            raise ValueError("pat boom")

        ms.generate_dependency_graphs = _ok_dep
        ms.generate_pattern_diagrams = _raise_pattern
        with pytest.raises(ValueError, match="pat boom"):
            ms.build_report(ast, tmp_path, "x", "svg")
    finally:
        ms.generate_dependency_graphs = original_dep
        ms.generate_pattern_diagrams = original_pattern

    class _DepGen:
        def generate_graph(
            self,
            _ast: ASTNode,
            output_path: str,
            _fmt: str,
            _engine: str,
        ) -> str:
            return output_path

        def generate_rule_graph(
            self,
            _ast: ASTNode,
            output_path: str,
            _fmt: str,
        ) -> str:
            return output_path

        def generate_module_graph(
            self,
            _ast: ASTNode,
            output_path: str,
            _fmt: str,
        ) -> str:
            return output_path

        def generate_complexity_graph(
            self,
            _ast: ASTNode,
            _cyclo: int,
            output_path: str,
            _fmt: str,
        ) -> str:
            return output_path

    orig = ms.DependencyGraphGenerator
    try:
        ms.DependencyGraphGenerator = _DepGen
        out = ms.generate_dependency_graph(ast, "full", str(tmp_path / "dep.svg"), "svg", "dot")
        assert out[0].endswith("dep.svg")
    finally:
        ms.DependencyGraphGenerator = orig
