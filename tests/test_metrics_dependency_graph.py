"""Real tests for dependency graph metrics (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier, MemberAccess
from yaraast.ast.rules import Import, Rule
from yaraast.metrics.dependency_graph import DependencyGraphGenerator
from yaraast.metrics.dependency_graph_utils import (
    DependencyGraph,
    analyze_dependencies,
    build_dependency_graph,
    export_dependency_graph,
    find_circular_dependencies,
    generate_dot_graph,
    get_dependency_order,
)
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


def _parse_yara(code: str) -> YaraFile:
    parser = Parser()
    return parser.parse(dedent(code))


def test_dependency_graph_generator_outputs_dot_source(tmp_path: Path) -> None:
    code = """
    import "pe"

    rule base_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }

    rule uses_base : tag1 {
        condition:
            base_rule and pe.number_of_sections > 0
    }
    """
    ast = _parse_yara(code)

    generator = DependencyGraphGenerator()
    dot_source = generator.generate_graph(ast)
    assert "digraph" in dot_source

    stats = generator.get_dependency_stats()
    assert stats["total_rules"] == 2
    assert stats["total_imports"] == 1
    assert stats["rules_with_strings"] == 1
    assert stats["rules_using_modules"] == 1

    rule_graph = generator.generate_rule_graph(ast)
    assert "base_rule" in rule_graph
    assert "uses_base" in rule_graph

    module_graph = generator.generate_module_graph(ast)
    assert "Module: pe" in module_graph

    output_path = tmp_path / "deps.svg"
    rendered = generator.generate_graph(ast, output_path=str(output_path), format="svg")
    assert rendered.endswith(".svg")


def test_dependency_graph_generator_renders_rule_dependency_edges() -> None:
    ast = _parse_yara("""
    rule base_rule {
        condition:
            true
    }

    rule caller {
        condition:
            base_rule
    }
    """)

    generator = DependencyGraphGenerator()
    dot_source = generator.generate_rule_graph(ast)
    stats = generator.get_dependency_stats()

    assert generator.dependencies["caller"] == {"base_rule"}
    assert "caller -> base_rule" in dot_source
    assert stats["rules_with_deps"] == 1
    assert stats["total_dependencies"] == 1


def test_dependency_graph_generator_does_not_treat_module_member_root_as_rule_dependency() -> None:
    ast = YaraFile(
        imports=[Import("pe")],
        rules=[
            Rule(name="pe", condition=BooleanLiteral(True)),
            Rule(
                name="check",
                condition=MemberAccess(
                    object=Identifier("pe"),
                    member="number_of_sections",
                ),
            ),
        ],
    )

    generator = DependencyGraphGenerator()
    generator.visit(ast)

    assert generator.dependencies["check"] == set()
    assert generator.module_references["check"] == {"pe"}


def test_dependency_graph_tracks_module_reference_in_function_call_receiver() -> None:
    ast = parse_yara_source('import "pe"\nrule check { condition: pe.signatures[0].valid_on(0) }')

    generator = DependencyGraphGenerator()
    generator.visit(ast)

    assert generator.module_references["check"] == {"pe"}


def test_dependency_graph_variant_generators_reset_between_inputs() -> None:
    first_ast = _parse_yara("""
    import "pe"

    rule old_rule {
        strings:
            $a = "old"
        condition:
            $a and pe.number_of_sections > 0
    }
    """)
    second_ast = _parse_yara("""
    import "math"

    rule new_rule {
        condition:
            math.entropy(0, filesize) > 0
    }
    """)
    generator = DependencyGraphGenerator()

    assert "old_rule" in generator.generate_rule_graph(first_ast)
    second_rule_graph = generator.generate_rule_graph(second_ast)
    assert "new_rule" in second_rule_graph
    assert "old_rule" not in second_rule_graph

    assert "Module: pe" in generator.generate_module_graph(first_ast)
    second_module_graph = generator.generate_module_graph(second_ast)
    assert "Module: math" in second_module_graph
    assert "Module: pe" not in second_module_graph

    assert "old_rule" in generator.generate_complexity_graph(first_ast, {"old_rule": 1})
    second_complexity_graph = generator.generate_complexity_graph(second_ast, {"new_rule": 1})
    assert "new_rule" in second_complexity_graph
    assert "old_rule" not in second_complexity_graph


def test_dependency_graph_build_and_analysis() -> None:
    code = """
    rule a { condition: true }
    rule b { condition: a }
    rule c { condition: a and b }
    """
    ast = _parse_yara(code)
    graph = build_dependency_graph(ast)

    assert "a" in graph.edges["b"]
    assert "a" in graph.edges["c"]
    assert "b" in graph.edges["c"]

    analysis = analyze_dependencies(ast)
    stats = analysis["stats"]
    assert stats["total_rules"] == 3
    assert stats["rules_with_deps"] == 2
    assert stats["total_dependencies"] >= 2


def test_dependency_graph_generator_traverses_yarax_conditions() -> None:
    ast = parse_yara_source("""
        import "pe"

        rule yarax_modules {
            condition:
                with xs = [1]: match xs {
                    _ => pe.number_of_sections > 0,
                }
        }
        """)

    generator = DependencyGraphGenerator()
    generator.visit(ast)

    assert "pe" in generator.module_references["yarax_modules"]


def test_dependency_graph_generator_respects_yarax_module_name_shadowing() -> None:
    ast = parse_yara_source("""
        import "pe"

        rule shadowed_module {
            condition:
                with pe = {"number_of_sections": 1}: pe.number_of_sections > 0
        }

        rule shadowed_module_function {
            condition:
                with pe = 1: pe.is_pe()
        }

        rule declaration_value_uses_module {
            condition:
                with local = pe.number_of_sections: local > 0
        }

        rule dollar_local_does_not_shadow_module {
            strings:
                $pe = "x"
            condition:
                with $pe = 1: pe.number_of_sections > 0
        }
        """)

    generator = DependencyGraphGenerator()
    generator.visit(ast)

    assert "pe" not in generator.module_references["shadowed_module"]
    assert "pe" not in generator.module_references["shadowed_module_function"]
    assert "pe" in generator.module_references["declaration_value_uses_module"]
    assert "pe" in generator.module_references["dollar_local_does_not_shadow_module"]


def test_dependency_graph_cycles_and_order(tmp_path: Path) -> None:
    graph = DependencyGraph()
    graph.add_edge("a", "b")
    graph.add_edge("b", "c")
    graph.add_edge("c", "a")

    cycles = find_circular_dependencies(graph)
    assert cycles

    order = get_dependency_order(graph)
    assert set(order) == {"a", "b", "c"}

    dot = generate_dot_graph(graph)
    assert "digraph Dependencies" in dot

    json_path = tmp_path / "deps.json"
    export_dependency_graph(graph, json_path, format="json")
    assert json_path.read_text(encoding="utf-8")

    dot_path = tmp_path / "deps.dot"
    export_dependency_graph(graph, dot_path, format="dot")
    assert "digraph" in dot_path.read_text(encoding="utf-8")

    loaded = DependencyGraph()
    loaded.from_dict(graph.to_dict())
    assert "b" in loaded.edges["a"]
