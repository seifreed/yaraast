"""Input validation tests for public YaraFile utility APIs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.cli.serialize_services import build_ast_info
from yaraast.codegen.pretty_printer import pretty_print
from yaraast.metrics.dependency_graph_utils import analyze_dependencies, build_dependency_graph
from yaraast.optimization.dead_code_eliminator import DeadCodeEliminator
from yaraast.shared.ast_analysis import ASTFormatter


@pytest.mark.parametrize(
    "function",
    [
        ASTFormatter().format_ast,
        pretty_print,
        build_ast_info,
        DeadCodeEliminator().eliminate,
        build_dependency_graph,
        analyze_dependencies,
    ],
)
@pytest.mark.parametrize("value", [None, 123, object()])
def test_public_yarafile_utilities_reject_invalid_inputs(
    function: Callable[[Any], object],
    value: object,
) -> None:
    with pytest.raises(TypeError, match="must be a YaraFile"):
        function(cast(Any, value))
