"""Additional tests for metrics_services helpers (no mocks)."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any, cast

import pytest

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.metrics import workflows as metrics_workflows
from yaraast.metrics.graphviz_errors import is_graphviz_error
from yaraast.parser import Parser


def _ast() -> YaraFile:
    code = """
rule a { condition: true }
rule b { condition: a }
""".strip()
    ast = Parser().parse(code)
    assert isinstance(ast, YaraFile)
    return ast


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
        metrics_workflows.determine_graph_output_path("/tmp/rules.yar", None, "full", "svg")
        == "rules_graph_full.svg"
    )
    assert (
        metrics_workflows.determine_graph_output_path("/tmp/rules.yar", "x.svg", "full", "svg")
        == "x.svg"
    )

    assert (
        metrics_workflows.determine_pattern_output_path("/tmp/rules.yar", None, "flow", "dot")
        == "rules_patterns_flow.dot"
    )
    assert (
        metrics_workflows.determine_pattern_output_path("/tmp/rules.yar", "x.dot", "flow", "dot")
        == "x.dot"
    )

    assert is_graphviz_error(Exception("ExecutableNotFound")) is True
    assert is_graphviz_error(Exception("failed to execute PosixPath('dot')")) is True
    assert is_graphviz_error(Exception("No such file or directory: PosixPath('dot')")) is True
    assert (
        is_graphviz_error(ModuleNotFoundError("No module named 'graphviz'", name="graphviz"))
        is True
    )
    graphviz_called_process = type(
        "CalledProcessError",
        (Exception,),
        {"__module__": "graphviz.backend.execute"},
    )
    assert is_graphviz_error(graphviz_called_process("graphviz dot failed")) is True
    assert is_graphviz_error(subprocess.CalledProcessError(1, ["not-dot"])) is False
    assert is_graphviz_error(FileNotFoundError("No such file or directory: rules.yar")) is False
    assert is_graphviz_error(Exception("dot product calculation failed")) is False
    assert is_graphviz_error(Exception("another error")) is False


def test_metrics_services_path_helpers_reject_empty_output_path() -> None:
    with pytest.raises(ValueError, match="output_path must not be empty"):
        metrics_workflows.determine_graph_output_path("/tmp/rules.yar", "", "full", "svg")
    with pytest.raises(ValueError, match="output_path must not be empty"):
        metrics_workflows.determine_pattern_output_path("/tmp/rules.yar", "", "flow", "dot")


def test_metrics_services_path_helpers_reject_directory_output_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="output_path must not be a directory"):
        metrics_workflows.determine_graph_output_path("/tmp/rules.yar", tmp_path, "full", "svg")
    with pytest.raises(ValueError, match="output_path must not be a directory"):
        metrics_workflows.determine_pattern_output_path("/tmp/rules.yar", tmp_path, "flow", "dot")


@pytest.mark.parametrize("output", [False, 0, object()])
def test_metrics_services_path_helpers_reject_invalid_output_path_types(output: Any) -> None:
    with pytest.raises(TypeError, match="output_path must be a file path"):
        metrics_workflows.determine_graph_output_path(
            "/tmp/rules.yar", cast(Any, output), "full", "svg"
        )
    with pytest.raises(TypeError, match="output_path must be a file path"):
        metrics_workflows.determine_pattern_output_path(
            "/tmp/rules.yar", cast(Any, output), "flow", "dot"
        )


@pytest.mark.parametrize("value", [None, False, 123, object(), b"rules.yar", "", "   "])
def test_metrics_services_path_helpers_reject_invalid_yara_file_values(value: Any) -> None:
    error_type = ValueError if isinstance(value, str) else TypeError
    with pytest.raises(error_type, match="yara_file must"):
        metrics_workflows.determine_graph_output_path(cast(Any, value), None, "full", "svg")
    with pytest.raises(error_type, match="yara_file must"):
        metrics_workflows.determine_pattern_output_path(cast(Any, value), None, "flow", "dot")


def test_metrics_services_path_helpers_reject_null_byte_yara_file() -> None:
    with pytest.raises(ValueError, match="yara_file must not contain null bytes"):
        metrics_workflows.determine_graph_output_path("\x00broken.yar", None, "full", "svg")
    with pytest.raises(ValueError, match="yara_file must not contain null bytes"):
        metrics_workflows.determine_pattern_output_path("\x00broken.yar", None, "flow", "dot")


@pytest.mark.parametrize("graph_type", [None, False, 123, object(), b"full", "", "   "])
def test_metrics_services_path_helpers_reject_invalid_graph_types(graph_type: Any) -> None:
    error_type = ValueError if isinstance(graph_type, str) else TypeError
    with pytest.raises(error_type, match="graph_type must"):
        metrics_workflows.determine_graph_output_path(
            "/tmp/rules.yar",
            None,
            cast(Any, graph_type),
            "svg",
        )


@pytest.mark.parametrize("pattern_type", [None, False, 123, object(), b"flow", "", "   "])
def test_metrics_services_path_helpers_reject_invalid_pattern_types(pattern_type: Any) -> None:
    error_type = ValueError if isinstance(pattern_type, str) else TypeError
    with pytest.raises(error_type, match="pattern_type must"):
        metrics_workflows.determine_pattern_output_path(
            "/tmp/rules.yar",
            None,
            cast(Any, pattern_type),
            "svg",
        )


@pytest.mark.parametrize("graph_type", ["../escape", "full/escape", "full\\escape"])
def test_metrics_services_path_helpers_reject_path_like_graph_types(graph_type: str) -> None:
    with pytest.raises(ValueError, match="graph_type must contain only letters and numbers"):
        metrics_workflows.determine_graph_output_path("/tmp/rules.yar", None, graph_type, "svg")


@pytest.mark.parametrize("pattern_type", ["../escape", "flow/escape", "flow\\escape"])
def test_metrics_services_path_helpers_reject_path_like_pattern_types(pattern_type: str) -> None:
    with pytest.raises(ValueError, match="pattern_type must contain only letters and numbers"):
        metrics_workflows.determine_pattern_output_path("/tmp/rules.yar", None, pattern_type, "svg")


@pytest.mark.parametrize("fmt", ["../escape", "svg/escape", "svg\\escape"])
def test_metrics_services_path_helpers_reject_path_like_output_formats(fmt: str) -> None:
    with pytest.raises(ValueError, match="output format must contain only letters and numbers"):
        metrics_workflows.determine_graph_output_path("/tmp/rules.yar", None, "full", fmt)
    with pytest.raises(ValueError, match="output format must contain only letters and numbers"):
        metrics_workflows.determine_pattern_output_path("/tmp/rules.yar", None, "flow", fmt)


@pytest.mark.parametrize("fmt", [None, False, 123, object(), b"svg", "", "   "])
def test_metrics_services_path_helpers_reject_invalid_output_formats(fmt: Any) -> None:
    error_type = ValueError if isinstance(fmt, str) else TypeError
    with pytest.raises(error_type, match="output format must"):
        metrics_workflows.determine_graph_output_path(
            "/tmp/rules.yar", None, "full", cast(Any, fmt)
        )
    with pytest.raises(error_type, match="output format must"):
        metrics_workflows.determine_pattern_output_path(
            "/tmp/rules.yar", None, "flow", cast(Any, fmt)
        )


def test_metrics_services_graph_and_pattern_generation_with_generators(tmp_path: Path) -> None:
    ast = _ast()
    dep = _DepGen()

    assert dep.generate_graph(ast, str(tmp_path / "f.svg"), "svg", "dot").endswith("f.svg")
    assert dep.generate_rule_graph(ast, str(tmp_path / "r.svg"), "svg").endswith("r.svg")
    assert dep.generate_module_graph(ast, str(tmp_path / "m.svg"), "svg").endswith("m.svg")
    assert dep.generate_complexity_graph(ast, 1, str(tmp_path / "c.svg"), "svg").endswith("c.svg")

    pat = _PatternGen()
    assert pat.generate_pattern_flow_diagram(ast, str(tmp_path / "flow.svg"), "svg").endswith(
        "flow.svg"
    )
    assert pat.generate_pattern_complexity_diagram(ast, str(tmp_path / "cx.svg"), "svg").endswith(
        "cx.svg"
    )
    assert pat.generate_pattern_similarity_diagram(ast, str(tmp_path / "sim.svg"), "svg").endswith(
        "sim.svg"
    )
    assert pat.generate_hex_pattern_diagram(ast, str(tmp_path / "hex.svg"), "svg").endswith(
        "hex.svg"
    )


def test_metrics_services_html_and_wrapper_functions(tmp_path: Path) -> None:
    ast = _ast()

    name_i = metrics_workflows.generate_html_tree(
        ast,
        tmp_path,
        "rules",
        interactive=True,
        generator_factory=_HtmlGen,
    )
    assert name_i == "rules_tree.html"

    name_s = metrics_workflows.generate_html_tree(
        ast,
        tmp_path,
        "rules2",
        interactive=False,
        generator_factory=_HtmlGen,
    )
    assert name_s == "rules2_tree.html"

    dep_files = metrics_workflows.generate_dependency_graphs(
        ast,
        tmp_path,
        "rules",
        "svg",
        generator_factory=_DepGen,
    )
    assert len(dep_files) == 3

    pat_files = metrics_workflows.generate_pattern_diagrams(
        ast,
        tmp_path,
        "rules",
        "svg",
        generator_factory=_PatternGen,
    )
    assert len(pat_files) == 3


def test_metrics_services_build_report_and_generator_none(tmp_path: Path) -> None:
    ast = _ast()

    report = metrics_workflows.build_report(ast, tmp_path, "rules", "svg")
    assert report.base_name == "rules"
    assert any(name.endswith("_tree.html") for name in report.generated_files)

    out = _PatternGen().generate_pattern_flow_diagram(ast, str(tmp_path / "flow_real.svg"), "svg")
    assert out.endswith("flow_real.svg")


def test_metrics_services_build_report_rejects_output_dir_under_symlink_ancestor(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    output_dir = link / "reports"
    output_dir.mkdir()

    with pytest.raises(ValueError, match="output_dir must not traverse a symlink"):
        metrics_workflows.build_report(_ast(), output_dir, "rules", "svg")


def test_metrics_services_build_report_rejects_path_like_image_format(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="image_format must contain only letters and numbers"):
        metrics_workflows.build_report(_ast(), tmp_path, "rules", "svg/../../pwn")


def test_metrics_services_error_paths_and_dependency_generator_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ast = _ast()

    with pytest.raises(RuntimeError, match="graphviz"):
        metrics_workflows.generate_dependency_graphs(
            ast, tmp_path, "x", "svg", generator_factory=None
        )

    original_dep = metrics_workflows.generate_dependency_graphs
    original_pattern = metrics_workflows.generate_pattern_diagrams
    try:

        def _raise_dep(
            ast: YaraFile,
            output_dir: Path,
            base_name: str,
            image_format: str,
            generator_factory: Any = None,
        ) -> list[str]:
            _ = image_format
            raise ValueError("dep boom")

        metrics_workflows.generate_dependency_graphs = _raise_dep
        with pytest.raises(ValueError, match="dep boom"):
            metrics_workflows.build_report(ast, tmp_path, "x", "svg")

        def _ok_dep(
            ast: YaraFile,
            output_dir: Path,
            base_name: str,
            image_format: str,
            generator_factory: Any = None,
        ) -> list[str]:
            _ = image_format
            return []

        def _raise_pattern(
            ast: YaraFile,
            output_dir: Path,
            base_name: str,
            image_format: str,
            generator_factory: Any = None,
        ) -> list[str]:
            _ = image_format
            raise ValueError("pat boom")

        metrics_workflows.generate_dependency_graphs = _ok_dep
        metrics_workflows.generate_pattern_diagrams = _raise_pattern
        with pytest.raises(ValueError, match="pat boom"):
            metrics_workflows.build_report(ast, tmp_path, "x", "svg")
    finally:
        metrics_workflows.generate_dependency_graphs = original_dep
        metrics_workflows.generate_pattern_diagrams = original_pattern

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

    out = _DepGen().generate_graph(ast, str(tmp_path / "dep.svg"), "svg", "dot")
    assert out.endswith("dep.svg")
