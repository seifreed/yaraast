"""More real tests for workspace resolution and analysis."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Include, Rule
from yaraast.resolution.include_resolver import ResolvedFile
from yaraast.resolution.workspace import (
    FileAnalysisResult,
    Workspace,
    WorkspaceAnalyzer,
    WorkspaceReport,
)


def _write(path: Path, content: str) -> Path:
    path.write_text(content.strip() + "\n", encoding="utf-8")
    return path


def test_workspace_add_file_error_paths_and_getters(tmp_path: Path) -> None:
    root = tmp_path
    workspace = Workspace(str(root))

    missing = workspace.add_file("missing.yar")
    assert missing.errors
    assert "File not found:" in missing.errors[0]

    bad_file = _write(root / "bad.yar", 'rule bad { condition: "oops"')
    bad = workspace.add_file(str(bad_file))
    assert bad.errors
    assert "Parse error:" in bad.errors[0]

    a = _write(root / "a.yar", 'include "b.yar"\nrule a { condition: true }')
    _write(root / "b.yar", 'include "a.yar"\nrule b { condition: true }')
    circular = workspace.add_file(str(a))
    assert circular.errors
    assert "Circular include:" in circular.errors[0]

    ok = _write(root / "ok.yar", "rule ok_rule { condition: true }")
    added = workspace.add_file("ok.yar")
    assert added.resolved is not None
    assert added.path == ok

    assert workspace.get_all_files()
    all_rules = workspace.get_all_rules()
    assert ("ok_rule", str(ok)) in all_rules
    found = workspace.find_rule("ok_rule")
    assert found is not None and found[0] == str(ok)
    assert isinstance(workspace.get_file_dependencies(str(ok)), set)
    assert isinstance(workspace.get_file_dependents(str(ok)), set)


def test_workspace_add_directory_relative_parallel_analysis_and_global_issues(
    tmp_path: Path,
) -> None:
    root = tmp_path
    sub = root / "rules"
    sub.mkdir()
    nested = sub / "nested"
    nested.mkdir()

    _write(
        sub / "one.yar",
        """
        include "missing.yar"
        rule dup_rule {
            strings:
                $a = "x"
            condition:
                $a
        }
        """,
    )
    _write(
        nested / "two.yar",
        """
        rule dup_rule {
            condition:
                true
        }
        """,
    )
    _write(
        sub / "three.txt",
        """
        rule ignored_rule {
            condition:
                true
        }
        """,
    )

    workspace = Workspace(str(root))
    workspace.add_directory("rules", pattern="*.yar", recursive=True)
    assert len(workspace.files) == 2

    report = workspace.analyze(parallel=True, max_workers=2)
    assert report.files_analyzed == 2
    assert report.total_rules == 2
    assert report.statistics["file_count"] == 2
    assert report.statistics["rule_count"] == 1
    assert report.statistics["include_count"] == 1
    assert report.statistics["rule_name_conflicts"] == 1
    assert "dup_rule" in report.statistics["conflicting_rules"]
    assert any("Cannot resolve include 'missing.yar'" in err for err in report.global_errors)
    assert any("Rule 'dup_rule' defined in multiple files" in err for err in report.global_errors)
    assert set(report.file_results) == set(workspace.files)


def test_workspace_sequential_analysis_with_relative_directory_and_nonrecursive(
    tmp_path: Path,
) -> None:
    root = tmp_path
    (root / "top").mkdir()
    (root / "top" / "child").mkdir()

    first = _write(root / "top" / "a.yar", "rule a { condition: true }")
    _write(root / "top" / "child" / "b.yar", "rule b { condition: true }")

    workspace = Workspace(str(root))
    workspace.add_directory("top", recursive=False)
    assert len(workspace.files) == 1
    assert str(first) in workspace.files

    report = workspace.analyze(parallel=False)
    assert report.files_analyzed == 1
    assert report.file_results[str(first)].resolved is not None


def test_workspace_analysis_handles_unresolved_results_analysis_errors_and_cycles(
    tmp_path: Path,
) -> None:
    workspace = Workspace(str(tmp_path))

    good_path = tmp_path / "good.yar"
    broken_path = tmp_path / "broken.yar"
    unresolved_path = tmp_path / "unresolved.yar"
    cycle_path = tmp_path / "cycle.yar"

    workspace.files[str(good_path)] = FileAnalysisResult(
        path=good_path,
        resolved=ResolvedFile(
            path=good_path,
            content="rule good { condition: true }",
            ast=YaraFile(rules=[Rule(name="good", condition=BooleanLiteral(True))]),
            checksum="good",
        ),
    )
    workspace.files[str(broken_path)] = FileAnalysisResult(
        path=broken_path,
        resolved=ResolvedFile(
            path=broken_path,
            content="rule broken { condition: true }",
            ast=YaraFile(rules=[Rule(name="broken", strings=None, condition=BooleanLiteral(True))]),
            checksum="broken",
        ),
    )
    workspace.files[str(unresolved_path)] = FileAnalysisResult(path=unresolved_path)

    workspace.dependency_graph.add_file(
        cycle_path,
        YaraFile(includes=[Include(path=str(cycle_path))]),
    )

    report = workspace.analyze(parallel=False)

    assert report.files_analyzed == 2
    assert report.file_results[str(unresolved_path)].resolved is None
    assert any("Analysis error:" in err for err in report.file_results[str(broken_path)].errors)
    assert any("Dependency cycle detected:" in err for err in report.global_errors)


def test_workspace_parallel_analysis_records_future_failures(tmp_path: Path) -> None:
    workspace = Workspace(str(tmp_path))

    good_path = tmp_path / "good.yar"
    bad_path = tmp_path / "bad.yar"
    workspace.files[str(good_path)] = FileAnalysisResult(
        path=good_path,
        resolved=ResolvedFile(
            path=good_path,
            content="rule good { condition: true }",
            ast=YaraFile(rules=[Rule(name="good", condition=BooleanLiteral(True))]),
            checksum="good",
        ),
    )
    workspace.files[str(bad_path)] = FileAnalysisResult(
        path=bad_path,
        resolved=cast(ResolvedFile, object()),
    )

    analyzer = WorkspaceAnalyzer(workspace)
    report = WorkspaceReport(
        files_analyzed=0,
        total_rules=0,
        total_includes=0,
        total_imports=0,
        dependency_graph=workspace.dependency_graph,
        file_results={},
    )
    analyzer._analyze_parallel(report, max_workers=2)

    assert set(report.file_results) == {str(good_path), str(bad_path)}
    assert any("Analysis error:" in err for err in report.file_results[str(bad_path)].errors)
