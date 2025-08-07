"""Tests for multi-file resolution functionality."""

import tempfile
from pathlib import Path

import pytest

from yaraast.resolution import DependencyGraph, IncludeResolver, Workspace


def create_temp_file(directory, name, content):
    """Helper to create temporary YARA files."""
    file_path = directory / name
    file_path.write_text(content)
    return file_path


class TestIncludeResolver:
    """Test include file resolution."""

    def test_basic_include_resolution(self) -> None:
        """Test basic include file resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create base rule
            base_content = """
include "common.yar"

rule base_rule {
    condition:
        true
}
"""
            # Create included file
            common_content = """
rule common_rule {
    strings:
        $common = "common"
    condition:
        $common
}
"""
            base_file = create_temp_file(tmpdir, "base.yar", base_content)
            create_temp_file(tmpdir, "common.yar", common_content)

            # Resolve
            resolver = IncludeResolver([str(tmpdir)])
            resolved = resolver.resolve_file(str(base_file))

            # Verify
            assert resolved.path.resolve() == base_file.resolve()
            assert len(resolved.includes) == 1
            assert resolved.includes[0].path.name == "common.yar"
            assert len(resolved.includes[0].ast.rules) == 1
            assert resolved.includes[0].ast.rules[0].name == "common_rule"

    def test_nested_includes(self) -> None:
        """Test nested include resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create files with nested includes
            # main.yar -> lib1.yar -> lib2.yar
            main_content = """
include "lib1.yar"

rule main_rule {
    condition: true
}
"""
            lib1_content = """
include "lib2.yar"

rule lib1_rule {
    condition: true
}
"""
            lib2_content = """
rule lib2_rule {
    condition: true
}
"""
            main_file = create_temp_file(tmpdir, "main.yar", main_content)
            create_temp_file(tmpdir, "lib1.yar", lib1_content)
            create_temp_file(tmpdir, "lib2.yar", lib2_content)

            # Resolve
            resolver = IncludeResolver([str(tmpdir)])
            resolved = resolver.resolve_file(str(main_file))

            # Verify structure
            assert len(resolved.includes) == 1
            assert resolved.includes[0].path.name == "lib1.yar"
            assert len(resolved.includes[0].includes) == 1
            assert resolved.includes[0].includes[0].path.name == "lib2.yar"

            # Verify all rules are accessible
            all_rules = resolved.get_all_rules()
            rule_names = [r.name for r in all_rules]
            assert "main_rule" in rule_names
            assert "lib1_rule" in rule_names
            assert "lib2_rule" in rule_names

    def test_circular_include_detection(self) -> None:
        """Test detection of circular includes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create circular includes: a.yar -> b.yar -> a.yar
            a_content = """
include "b.yar"
rule rule_a { condition: true }
"""
            b_content = """
include "a.yar"
rule rule_b { condition: true }
"""
            a_file = create_temp_file(tmpdir, "a.yar", a_content)
            create_temp_file(tmpdir, "b.yar", b_content)

            # Try to resolve - should raise RecursionError
            resolver = IncludeResolver([str(tmpdir)])
            with pytest.raises(RecursionError, match="Circular include detected"):
                resolver.resolve_file(str(a_file))

    def test_include_path_searching(self) -> None:
        """Test include path searching in multiple directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create directory structure
            main_dir = tmpdir / "main"
            lib_dir = tmpdir / "lib"
            main_dir.mkdir()
            lib_dir.mkdir()

            # Create files in different directories
            main_content = """
include "library.yar"
rule main_rule { condition: true }
"""
            lib_content = """
rule library_rule { condition: true }
"""
            main_file = create_temp_file(main_dir, "main.yar", main_content)
            create_temp_file(lib_dir, "library.yar", lib_content)

            # Resolve with search paths
            resolver = IncludeResolver([str(main_dir), str(lib_dir)])
            resolved = resolver.resolve_file(str(main_file))

            # Verify include was found in lib directory
            assert len(resolved.includes) == 1
            assert resolved.includes[0].path.parent.resolve() == lib_dir.resolve()

    def test_caching(self) -> None:
        """Test file caching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            content = "rule test { condition: true }"
            test_file = create_temp_file(tmpdir, "test.yar", content)

            resolver = IncludeResolver()

            # First resolution
            resolved1 = resolver.resolve_file(str(test_file))

            # Second resolution should use cache
            resolved2 = resolver.resolve_file(str(test_file))

            # Should be the same object
            assert resolved1 is resolved2

            # Modify file
            test_file.write_text("rule modified { condition: false }")

            # Should get new object
            resolved3 = resolver.resolve_file(str(test_file))
            assert resolved3 is not resolved1
            assert resolved3.ast.rules[0].name == "modified"


class TestWorkspace:
    """Test workspace functionality."""

    def test_workspace_add_file(self) -> None:
        """Test adding files to workspace."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create test file
            content = """
rule test_rule {
    strings:
        $test = "test"
    condition:
        $test
}
"""
            test_file = create_temp_file(tmpdir, "test.yar", content)

            # Create workspace and add file
            workspace = Workspace(str(tmpdir))
            result = workspace.add_file(str(test_file))

            # Verify
            assert result.path == test_file
            assert result.resolved is not None
            assert len(result.errors) == 0
            assert len(result.resolved.ast.rules) == 1

    def test_workspace_add_directory(self) -> None:
        """Test adding directory to workspace."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create multiple files
            for i in range(3):
                content = f"rule rule_{i} {{ condition: true }}"
                create_temp_file(tmpdir, f"file_{i}.yar", content)

            # Create subdirectory with more files
            subdir = tmpdir / "subdir"
            subdir.mkdir()
            for i in range(2):
                content = f"rule sub_rule_{i} {{ condition: true }}"
                create_temp_file(subdir, f"sub_{i}.yar", content)

            # Add directory
            workspace = Workspace(str(tmpdir))
            workspace.add_directory(str(tmpdir), recursive=True)

            # Verify all files were added
            assert len(workspace.files) == 5

            # Test non-recursive
            workspace2 = Workspace(str(tmpdir))
            workspace2.add_directory(str(tmpdir), recursive=False)
            assert len(workspace2.files) == 3

    def test_workspace_analysis(self) -> None:
        """Test workspace analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create files with various issues
            good_content = """
rule good_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"""
            bad_content = """
rule bad_rule {
    strings:
        $a = "test"
    condition:
        $b  // undefined string
}
"""
            unused_content = """
rule unused_strings {
    strings:
        $used = "used"
        $unused = "unused"
    condition:
        $used
}
"""
            create_temp_file(tmpdir, "good.yar", good_content)
            create_temp_file(tmpdir, "bad.yar", bad_content)
            create_temp_file(tmpdir, "unused.yar", unused_content)

            # Analyze workspace
            workspace = Workspace(str(tmpdir))
            workspace.add_directory(str(tmpdir))
            report = workspace.analyze(parallel=False)

            # Verify report
            assert report.files_analyzed == 3
            assert report.total_rules == 3
            assert report.statistics["total_warnings"] > 0  # unused string warning
            assert report.statistics["total_type_errors"] == 0  # type errors are different

    def test_dependency_graph(self) -> None:
        """Test dependency graph building."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create files with dependencies
            main_content = """
import "pe"
include "lib.yar"

rule main_rule {
    condition:
        pe.sections[0].name == ".text"
}
"""
            lib_content = """
import "math"

rule lib_rule {
    condition:
        math.entropy(0, 100) > 7.0
}
"""
            main_file = create_temp_file(tmpdir, "main.yar", main_content)
            create_temp_file(tmpdir, "lib.yar", lib_content)

            # Build workspace
            workspace = Workspace(str(tmpdir))
            workspace.add_file(str(main_file))

            # Check dependency graph
            graph = workspace.dependency_graph

            # Main file should depend on pe module and lib.yar
            main_deps = graph.get_file_dependencies(str(main_file))
            assert "pe" in main_deps

            # Check graph statistics
            stats = graph.get_statistics()
            assert stats["file_count"] >= 1
            assert stats["module_count"] >= 1
            assert stats["rule_count"] >= 1

    def test_find_rule(self) -> None:
        """Test finding rules in workspace."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create files with rules
            content1 = "rule unique_rule { condition: true }"
            content2 = "rule another_rule { condition: false }"

            file1 = create_temp_file(tmpdir, "file1.yar", content1)
            file2 = create_temp_file(tmpdir, "file2.yar", content2)

            workspace = Workspace(str(tmpdir))
            workspace.add_file(str(file1))
            workspace.add_file(str(file2))

            # Find rules
            result = workspace.find_rule("unique_rule")
            assert result is not None
            assert result[0] == str(file1)
            assert result[1].name == "unique_rule"

            result = workspace.find_rule("another_rule")
            assert result is not None
            assert result[0] == str(file2)

            result = workspace.find_rule("nonexistent")
            assert result is None


class TestDependencyGraph:
    """Test dependency graph functionality."""

    def test_cycle_detection(self) -> None:
        """Test cycle detection in dependency graph."""
        graph = DependencyGraph()

        # Create nodes with cycle: A -> B -> C -> A
        from yaraast.resolution.dependency_graph import DependencyNode

        graph.nodes["A"] = graph.nodes.get("A", DependencyNode("A", "file"))
        graph.nodes["B"] = graph.nodes.get("B", DependencyNode("B", "file"))
        graph.nodes["C"] = graph.nodes.get("C", DependencyNode("C", "file"))

        graph.nodes["A"].dependencies.add("B")
        graph.nodes["B"].dependencies.add("C")
        graph.nodes["C"].dependencies.add("A")

        cycles = graph.find_cycles()
        assert len(cycles) > 0

    def test_dot_export(self) -> None:
        """Test DOT format export."""
        graph = DependencyGraph()

        # Create simple graph
        from yaraast.ast.base import YaraFile
        from yaraast.ast.rules import Rule

        # Add a file node
        ast = YaraFile(
            imports=[],
            includes=[],
            rules=[
                Rule(
                    name="test_rule",
                    modifiers=[],
                    tags=[],
                    meta={},
                    strings=[],
                    condition=None,
                ),
            ],
        )
        graph.add_file(Path("test.yar"), ast)

        # Export to DOT
        dot = graph.export_dot()

        # Verify DOT content
        assert "digraph YaraDependencies" in dot
        assert "test.yar" in dot
        assert "test_rule" in dot
