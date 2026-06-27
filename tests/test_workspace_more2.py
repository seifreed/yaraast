"""More real tests for workspace resolution and analysis."""

from __future__ import annotations

import os
from pathlib import Path
from threading import Event
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Include, Rule
from yaraast.ast.strings import StringDefinition
from yaraast.errors import ValidationError
from yaraast.resolution.include_resolver import IncludeResolver, ResolvedFile
from yaraast.resolution.workspace import (
    FileAnalysisResult,
    Workspace,
    WorkspaceAnalyzer,
    WorkspaceReport,
)


def _write(path: Path, content: str) -> Path:
    path.write_text(content.strip() + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("root_path", ["", "   ", "\t"])
def test_workspace_rejects_empty_root_path(root_path: str) -> None:
    with pytest.raises(ValueError, match="root_path must not be empty"):
        Workspace(root_path)


@pytest.mark.parametrize("root_path", [False, 0, object()])
def test_workspace_rejects_invalid_root_path_types(root_path: Any) -> None:
    with pytest.raises(TypeError, match="root_path must be a path"):
        Workspace(cast(Any, root_path))


def test_workspace_accepts_pathlike_root_path(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path)

    assert workspace.root_path == tmp_path


def test_workspace_normalizes_file_uri_root_path(tmp_path: Path) -> None:
    workspace = Workspace(f"file://{tmp_path}")

    assert workspace.root_path == tmp_path


def test_workspace_preserves_symlinked_ancestor_path(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    workspace_root = link / "workspace"
    workspace_root.mkdir()
    rule_file = _write(workspace_root / "leak.yar", "rule leak { condition: true }")

    workspace = Workspace(root_path=workspace_root)
    result = workspace.add_file("leak.yar")

    assert result.path == rule_file
    assert list(workspace.files) == [str(rule_file)]
    assert workspace.get_all_rules() == [("leak", str(rule_file))]


def test_workspace_rejects_invalid_file_uri_root_path() -> None:
    with pytest.raises(ValueError, match="root_path must be a valid file URI or path"):
        Workspace("file://example.com/tmp/ws")


def test_workspace_rejects_symlinked_root_path(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="root_path must not be a symlink"):
        Workspace(link)


def test_workspace_rejects_file_root_path(tmp_path: Path) -> None:
    root_file = tmp_path / "not_a_directory"
    root_file.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError, match="root_path must be a directory"):
        Workspace(root_file)


def test_workspace_rejects_inaccessible_root_path() -> None:
    with pytest.raises(ValueError, match="path could not be accessed"):
        Workspace("a" * 5000)


@pytest.mark.parametrize("file_path", ["", "   ", "\t"])
def test_workspace_add_file_rejects_empty_file_path(
    tmp_path: Path,
    file_path: str,
) -> None:
    workspace = Workspace(str(tmp_path))

    with pytest.raises(ValueError, match="file_path must not be empty"):
        workspace.add_file(file_path)


@pytest.mark.parametrize("file_path", [None, False, 0, object(), b"rule.yar"])
def test_workspace_add_file_rejects_invalid_file_path_types(tmp_path: Path, file_path: Any) -> None:
    workspace = Workspace(str(tmp_path))

    with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
        workspace.add_file(cast(Any, file_path))


def test_workspace_add_file_error_paths_and_getters(tmp_path: Path) -> None:
    root = tmp_path
    workspace = Workspace(str(root))

    missing = workspace.add_file("missing.yar")
    assert missing.errors
    assert "File not found:" in missing.errors[0]
    assert "Cannot find YARA file" in missing.errors[0]

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

    assert workspace.files
    all_rules = workspace.get_all_rules()
    assert ("ok_rule", str(ok)) in all_rules
    found = workspace.find_rule("ok_rule")
    assert found is not None and found[0] == str(ok)
    assert isinstance(workspace.get_file_dependencies(str(ok)), set)
    assert isinstance(workspace.get_file_dependents(str(ok)), set)


def test_workspace_add_file_rejects_paths_outside_root(tmp_path: Path) -> None:
    outside_root = tmp_path.parent / f"{tmp_path.name}_escape"
    outside_root.mkdir()
    _write(outside_root / "escape.yar", "rule escape { condition: true }")

    workspace = Workspace(str(tmp_path))

    with pytest.raises(ValueError, match="file_path must stay within root_path"):
        workspace.add_file(f"../{outside_root.name}/escape.yar")


def test_workspace_add_directory_rejects_paths_outside_root(tmp_path: Path) -> None:
    outside_root = tmp_path.parent / f"{tmp_path.name}_scan_escape"
    nested = outside_root / "rules"
    nested.mkdir(parents=True)
    _write(nested / "escape.yar", "rule escape { condition: true }")

    workspace = Workspace(str(tmp_path))

    with pytest.raises(ValueError, match="directory must stay within root_path"):
        workspace.add_directory(f"../{outside_root.name}")


def test_workspace_missing_include_keeps_resolved_sibling_include(
    tmp_path: Path,
) -> None:
    root = tmp_path
    main = _write(
        root / "main.yar",
        """
        include "child.yar"
        include "missing.yar"
        rule main { condition: true }
        """,
    )
    child = _write(root / "child.yar", "rule child { condition: true }")

    workspace = Workspace(root_path=root, search_paths=[str(root)])
    result = workspace.add_file(main)
    report = workspace.analyze(parallel=False)

    assert result.resolved is not None
    assert [included.path for included in result.resolved.includes] == [child.resolve()]
    assert str(child.resolve()) in workspace.get_file_dependencies(str(main))
    assert any("Cannot resolve include 'missing.yar'" in err for err in report.global_errors)
    assert not any("Cannot resolve include 'child.yar'" in err for err in report.global_errors)


def test_workspace_missing_include_is_not_satisfied_by_matching_basename(
    tmp_path: Path,
) -> None:
    root = tmp_path
    nested = root / "dir"
    nested.mkdir()
    main = _write(
        root / "main.yar",
        """
        include "dir/child.yar"
        include "child.yar"
        rule main { condition: true }
        """,
    )
    child = _write(nested / "child.yar", "rule child { condition: true }")

    workspace = Workspace(root_path=root, search_paths=[str(root)])
    result = workspace.add_file(main)
    report = workspace.analyze(parallel=False)

    assert result.resolved is not None
    assert [included.path for included in result.resolved.includes] == [child.resolve()]
    assert any("Cannot resolve include 'child.yar'" in err for err in report.global_errors)
    assert not any("Cannot resolve include 'dir/child.yar'" in err for err in report.global_errors)


@pytest.mark.parametrize("rule_name", [None, 1, b"ok_rule", object(), "", "   "])
def test_workspace_find_rule_rejects_invalid_rule_names(
    tmp_path: Path,
    rule_name: Any,
) -> None:
    workspace = Workspace(str(tmp_path))

    with pytest.raises(ValidationError, match="DependencyGraph rule name"):
        workspace.find_rule(cast(str, rule_name))


def test_workspace_add_file_reports_invalid_utf8(tmp_path: Path) -> None:
    rule_file = tmp_path / "invalid.yar"
    rule_file.write_bytes(b"\xff")
    workspace = Workspace(str(tmp_path))

    result = workspace.add_file(rule_file)

    assert result.errors == ["Parse error: YARA file must contain valid UTF-8 text"]


def test_workspace_add_file_propagates_internal_resolver_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = Workspace(str(tmp_path))

    def broken_resolve_file(file_path: str) -> ResolvedFile:
        raise AttributeError("resolver state missing")

    monkeypatch.setattr(workspace.include_resolver, "resolve_file", broken_resolve_file)

    with pytest.raises(AttributeError, match="resolver state missing"):
        workspace.add_file("broken.yar")


def test_workspace_rule_lookup_includes_resolved_include_trees(tmp_path: Path) -> None:
    root = tmp_path
    parent = _write(
        root / "parent.yar",
        'include "child.yar"\nrule parent_rule { condition: true }',
    )
    child = _write(root / "child.yar", "rule child_rule { condition: true }")

    workspace = Workspace(str(root))
    workspace.add_file(str(parent))

    all_rules = workspace.get_all_rules()
    child_rule = workspace.find_rule("child_rule")

    assert ("parent_rule", str(parent)) in all_rules
    assert ("child_rule", str(child.resolve())) in all_rules
    assert child_rule is not None
    assert child_rule[0] == str(child.resolve())
    assert child_rule[1].name == "child_rule"


def test_workspace_analysis_detects_conflicts_in_resolved_include_trees(
    tmp_path: Path,
) -> None:
    root = tmp_path
    parent = _write(
        root / "parent.yar",
        'include "child.yar"\nrule dup_rule { condition: true }',
    )
    child = _write(root / "child.yar", "rule dup_rule { condition: true }")

    workspace = Workspace(str(root))
    workspace.add_file(str(parent))
    report = workspace.analyze(parallel=False)

    assert report.statistics["rule_name_conflicts"] == 1
    assert report.statistics["conflicting_rules"]["dup_rule"] == [
        str(parent),
        str(child.resolve()),
    ]
    assert any("Rule 'dup_rule' defined in multiple files" in err for err in report.global_errors)


def test_workspace_dependency_graph_preserves_cross_file_duplicate_rules(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    first = _write(root / "first.yar", "rule dup { condition: true }")
    second = _write(root / "second.yar", "rule dup { condition: true }")
    caller = _write(root / "caller.yar", "rule caller { condition: dup }")

    workspace = Workspace(root_path=root, search_paths=[str(root)])
    workspace.add_file(first)
    workspace.add_file(second)
    workspace.add_file(caller)

    first_key = str(first.resolve())
    second_key = str(second.resolve())

    assert {"rule:dup#1", "rule:dup#2"}.issubset(workspace.dependency_graph.nodes)
    assert workspace.dependency_graph.file_rules[first_key] == {"dup#1"}
    assert workspace.dependency_graph.file_rules[second_key] == {"dup#2"}
    assert workspace.dependency_graph.rule_files["dup#1"] == first_key
    assert workspace.dependency_graph.rule_files["dup#2"] == second_key
    assert workspace.dependency_graph.get_statistics()["rule_count"] == 3
    assert workspace.dependency_graph.get_rule_dependencies("caller") == {
        "rule:dup#1",
        "rule:dup#2",
    }
    assert "rule:dup#1" in workspace.get_file_dependencies(first_key)
    assert "rule:dup#2" in workspace.get_file_dependencies(second_key)

    workspace.add_file(first)

    assert workspace.dependency_graph.file_rules[first_key] == {"dup#1"}
    assert workspace.dependency_graph.get_rule_dependencies("caller") == {
        "rule:dup#1",
        "rule:dup#2",
    }


def test_workspace_analysis_does_not_accumulate_warnings_between_runs(
    tmp_path: Path,
) -> None:
    rule_file = _write(
        tmp_path / "unused.yar",
        """
        rule unused {
            strings:
                $used = "used"
                $unused = "unused"
            condition:
                $used
        }
        """,
    )
    workspace = Workspace(str(tmp_path))
    workspace.add_file(str(rule_file))

    first = workspace.analyze(parallel=False)
    second = workspace.analyze(parallel=False)

    assert first.statistics["total_warnings"] == 1
    assert second.statistics["total_warnings"] == 1
    assert second.file_results[str(rule_file)].warnings == [
        "Rule 'unused': Unused string '$unused'"
    ]


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
    assert report.statistics["rule_count"] == 2
    assert report.statistics["graph_rule_count"] == 2
    assert report.statistics["include_count"] == 1
    assert report.statistics["rule_name_conflicts"] == 1
    assert "dup_rule" in report.statistics["conflicting_rules"]
    assert any("Cannot resolve include 'missing.yar'" in err for err in report.global_errors)
    assert any("Rule 'dup_rule' defined in multiple files" in err for err in report.global_errors)
    assert set(report.file_results) == set(workspace.files)


def test_workspace_dependency_graph_links_resolved_include_paths(tmp_path: Path) -> None:
    root = tmp_path
    parent = _write(root / "parent.yar", 'include "child.yar"\nrule parent { condition: true }')
    child = _write(root / "child.yar", "rule child { condition: true }")

    workspace = Workspace(str(root))
    workspace.add_file(str(parent))

    parent_key = str(parent.resolve())
    child_key = str(child.resolve())
    dependencies = workspace.get_file_dependencies(str(parent))
    dependents = workspace.get_file_dependents(str(child))

    assert child_key in dependencies
    assert parent_key in dependents
    assert workspace.dependency_graph.nodes[child_key].type == "file"
    assert workspace.dependency_graph.get_statistics()["file_count"] == 2


def test_workspace_readding_file_removes_stale_include_graph_nodes(tmp_path: Path) -> None:
    root = tmp_path
    parent = _write(root / "parent.yar", 'include "child.yar"\nrule parent { condition: true }')
    child = _write(root / "child.yar", "rule child { condition: true }")

    workspace = Workspace(str(root))
    workspace.add_file(str(parent))
    assert str(child.resolve()) in workspace.dependency_graph.nodes

    _write(parent, "rule parent { condition: true }")
    workspace.add_file(str(parent))

    assert str(child.resolve()) not in workspace.dependency_graph.nodes
    assert "rule:child" not in workspace.dependency_graph.nodes
    assert workspace.dependency_graph.get_statistics()["file_count"] == 1


def test_include_resolver_rechecks_cached_files_with_missing_includes(tmp_path: Path) -> None:
    parent = _write(
        tmp_path / "parent.yar",
        'include "child.yar"\nrule parent { condition: true }',
    )
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(FileNotFoundError, match=r"Cannot find include file 'child\.yar'"):
        resolver.resolve_file(str(parent))

    child = _write(tmp_path / "child.yar", "rule child { condition: true }")

    second = resolver.resolve_file(str(parent))

    assert [included.path for included in second.includes] == [child.resolve()]


def test_include_resolver_does_not_add_cwd_when_search_paths_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    (cwd / "common.yar").write_text("rule cwd { condition: true }\n", encoding="utf-8")
    main = explicit / "main.yar"
    main.write_text('include "common.yar"\nrule main { condition: true }', encoding="utf-8")

    monkeypatch.chdir(cwd)
    resolver = IncludeResolver([str(explicit)])

    with pytest.raises(FileNotFoundError, match=r"Cannot find include file 'common\.yar'"):
        resolver.resolve_file(str(main))


def test_include_resolver_rejects_invalid_search_paths() -> None:
    with pytest.raises(TypeError, match="IncludeResolver search_paths must be a list of strings"):
        IncludeResolver(cast(Any, "abc"))

    with pytest.raises(TypeError, match="IncludeResolver search_paths must be a list of strings"):
        IncludeResolver(cast(Any, ""))

    with pytest.raises(TypeError, match="IncludeResolver search_paths must be a list of strings"):
        IncludeResolver(cast(Any, ()))

    with pytest.raises(TypeError, match="IncludeResolver search_paths must be a list of strings"):
        IncludeResolver(cast(Any, [object()]))


def test_include_resolver_rejects_symlink_search_paths(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(real_dir, target_is_directory=True)

    with pytest.raises(ValueError, match="IncludeResolver search paths must not be symlinks"):
        IncludeResolver([str(link)])


@pytest.mark.parametrize("search_path", ["", "   ", "\t"])
def test_include_resolver_rejects_empty_search_path_entries(search_path: str) -> None:
    with pytest.raises(
        ValueError,
        match="IncludeResolver search_paths must not contain empty paths",
    ):
        IncludeResolver([search_path])


@pytest.mark.parametrize("env_value", [os.pathsep, "   ", "\t"])
def test_include_resolver_rejects_empty_env_search_path_entries(
    monkeypatch: pytest.MonkeyPatch,
    env_value: str,
) -> None:
    monkeypatch.setenv("YARA_INCLUDE_PATH", env_value)

    with pytest.raises(ValueError, match="YARA_INCLUDE_PATH must not contain empty paths"):
        IncludeResolver([])


def test_include_resolver_rejects_symlink_env_search_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(real_dir, target_is_directory=True)
    monkeypatch.setenv("YARA_INCLUDE_PATH", str(link))

    with pytest.raises(ValueError, match="IncludeResolver search paths must not be symlinks"):
        IncludeResolver([])


@pytest.mark.parametrize("file_path", ["", "   ", "\t"])
def test_include_resolver_rejects_empty_file_path(tmp_path: Path, file_path: str) -> None:
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(ValueError, match="file_path must not be empty"):
        resolver.resolve_file(file_path)

    with pytest.raises(ValueError, match="file_path must not be empty"):
        resolver.get_include_tree(file_path)


@pytest.mark.parametrize("file_path", [None, False, 123, object(), b"rule.yar"])
def test_include_resolver_rejects_invalid_file_path_types(
    tmp_path: Path,
    file_path: Any,
) -> None:
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
        resolver.resolve_file(cast(Any, file_path))


def test_include_resolver_accepts_pathlike_file_path(tmp_path: Path) -> None:
    rule_file = _write(tmp_path / "ok.yar", "rule ok { condition: true }")
    resolver = IncludeResolver([str(tmp_path)])

    resolved = resolver.resolve_file(rule_file)

    assert resolved.path == rule_file.resolve()


def test_include_resolver_reports_missing_root_file_context(tmp_path: Path) -> None:
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(FileNotFoundError, match=r"Cannot find YARA file 'missing\.yar'"):
        resolver.resolve_file("missing.yar")


def test_include_resolver_rejects_inaccessible_paths(tmp_path: Path) -> None:
    absolute = "/" + ("a" * 5000)
    relative = "a" * 5000

    with pytest.raises(ValueError, match="path could not be accessed"):
        IncludeResolver().resolve_file(absolute)

    with pytest.raises(ValueError, match="path could not be accessed"):
        IncludeResolver([str(tmp_path)])._find_file(relative, tmp_path)

    with pytest.raises(ValueError, match="path could not be accessed"):
        IncludeResolver([absolute])._find_file("rule.yar", None)


def test_include_resolver_rejects_invalid_utf8_file(tmp_path: Path) -> None:
    rule_file = tmp_path / "invalid.yar"
    rule_file.write_bytes(b"\xff")
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(ValueError, match="YARA file must contain valid UTF-8 text"):
        resolver.resolve_file(rule_file)


def test_include_resolver_reports_invalid_utf8_include_context(tmp_path: Path) -> None:
    parent = _write(
        tmp_path / "parent.yar",
        'include "invalid.yar"\nrule parent { condition: true }',
    )
    invalid = tmp_path / "invalid.yar"
    invalid.write_bytes(b"\xff")
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(ValueError, match="YARA include file must contain valid UTF-8 text"):
        resolver.resolve_file(parent)


def test_include_resolver_treats_directory_matches_as_unresolved(tmp_path: Path) -> None:
    directory = tmp_path / "not_a_rule.yar"
    directory.mkdir()
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(FileNotFoundError, match="Cannot find YARA file"):
        resolver.resolve_file(str(directory))


def test_include_resolver_rechecks_nested_cached_files_with_missing_includes(
    tmp_path: Path,
) -> None:
    parent = _write(
        tmp_path / "parent.yar",
        'include "child.yar"\nrule parent { condition: true }',
    )
    _write(
        tmp_path / "child.yar",
        'include "grandchild.yar"\nrule child { condition: true }',
    )
    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(FileNotFoundError, match=r"Cannot find include file 'grandchild\.yar'"):
        resolver.resolve_file(str(parent))

    grandchild = _write(tmp_path / "grandchild.yar", "rule grandchild { condition: true }")

    second = resolver.resolve_file(str(parent))

    assert [included.path for included in second.includes[0].includes] == [grandchild.resolve()]


def test_include_resolver_rejects_parent_relative_includes(tmp_path: Path) -> None:
    shared = _write(tmp_path / "shared.yar", "rule shared { condition: true }")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    main = _write(
        rules_dir / "main.yar",
        'include "../shared.yar"\nrule main { condition: true }',
    )

    with pytest.raises(FileNotFoundError):
        IncludeResolver().resolve_file(str(main))

    assert shared.exists()


def test_include_resolver_rejects_absolute_includes(tmp_path: Path) -> None:
    shared = _write(tmp_path / "shared.yar", "rule shared { condition: true }")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    main = _write(
        rules_dir / "main.yar",
        'include "' + str(shared.resolve()) + '"\nrule main { condition: true }',
    )

    with pytest.raises(FileNotFoundError):
        IncludeResolver().resolve_file(str(main))


def test_include_resolver_reports_missing_nested_includes(tmp_path: Path) -> None:
    main = _write(
        tmp_path / "main.yar",
        'include "missing.yar"\nrule main { condition: true }',
    )

    resolver = IncludeResolver([str(tmp_path)])

    with pytest.raises(
        FileNotFoundError,
        match=r"Cannot find include file 'missing\.yar'",
    ) as exc_info:
        resolver.resolve_file(str(main))

    assert str(exc_info.value).count(str(tmp_path)) == 1


def test_workspace_add_directory_default_includes_yara_extension(tmp_path: Path) -> None:
    root = tmp_path
    yar = _write(root / "classic.yar", "rule classic_yar { condition: true }")
    yara = _write(root / "classic_alt.yara", "rule classic_yara { condition: true }")
    yarax = _write(root / "native.yarax", "rule native_yarax { condition: true }")

    workspace = Workspace(str(root))
    workspace.add_directory(str(root))

    assert str(yar) in workspace.files
    assert str(yara) in workspace.files
    assert str(yarax) not in workspace.files


def test_workspace_add_directory_skips_symlinked_files_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.yar"
    outside.write_text("rule outside { condition: true }", encoding="utf-8")
    link = root / "linked.yar"
    link.symlink_to(outside)
    _write(root / "inside.yar", "rule inside { condition: true }")

    workspace = Workspace(str(root))
    workspace.add_directory(str(root))

    assert str(root / "inside.yar") in workspace.files
    assert str(link) not in workspace.files


def test_workspace_add_directory_deduplicates_symlink_aliases(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    real = _write(root / "real.yar", "rule real { condition: true }")
    alias = root / "alias.yar"
    alias.symlink_to(real)

    workspace = Workspace(str(root))
    workspace.add_directory(str(root))

    assert sorted(workspace.files) == [str(real.resolve())]


@pytest.mark.parametrize("directory", ["", "   ", "\t"])
def test_workspace_add_directory_rejects_empty_directory(
    tmp_path: Path,
    directory: str,
) -> None:
    workspace = Workspace(str(tmp_path))

    with pytest.raises(ValueError, match="directory must not be empty"):
        workspace.add_directory(directory)


@pytest.mark.parametrize("directory", [None, 123, object()])
def test_workspace_add_directory_rejects_invalid_directory_types(
    tmp_path: Path, directory: Any
) -> None:
    workspace = Workspace(str(tmp_path))

    with pytest.raises(TypeError, match="directory must be a string or path-like object"):
        workspace.add_directory(cast(Any, directory))


@pytest.mark.parametrize("recursive", [None, 1, "yes", object()])
def test_workspace_add_directory_rejects_invalid_recursive_types(
    tmp_path: Path, recursive: Any
) -> None:
    workspace = Workspace(str(tmp_path))

    with pytest.raises(TypeError, match="recursive must be a boolean"):
        workspace.add_directory(".", recursive=cast(bool, recursive))


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
            ast=YaraFile(
                rules=[
                    Rule(
                        name="broken",
                        strings=cast(list[StringDefinition], None),
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
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


def test_workspace_analysis_propagates_internal_rule_analyzer_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule_file = _write(tmp_path / "ok.yar", "rule ok { condition: true }")
    workspace = Workspace(str(tmp_path))
    workspace.add_file(str(rule_file))

    class BrokenRuleAnalyzer:
        def analyze(self, ast: YaraFile) -> dict[str, object]:
            raise AttributeError("rule analyzer state missing")

    monkeypatch.setattr(
        "yaraast.resolution.workspace_analysis.RuleAnalyzer",
        BrokenRuleAnalyzer,
    )

    with pytest.raises(AttributeError, match="rule analyzer state missing"):
        workspace.analyze(parallel=False)


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
        resolved=ResolvedFile(
            path=bad_path,
            content="rule bad { condition: true }",
            ast=YaraFile(
                rules=[
                    Rule(
                        name="bad",
                        strings=cast(list[StringDefinition], None),
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            checksum="bad",
        ),
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


def test_workspace_parallel_analysis_propagates_internal_future_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = Workspace(str(tmp_path))
    for name in ("good", "bad"):
        path = tmp_path / f"{name}.yar"
        workspace.files[str(path)] = FileAnalysisResult(
            path=path,
            resolved=ResolvedFile(
                path=path,
                content=f"rule {name} {{ condition: true }}",
                ast=YaraFile(rules=[Rule(name=name, condition=BooleanLiteral(True))]),
                checksum=name,
            ),
        )

    original_analyze_file = WorkspaceAnalyzer._analyze_file

    def broken_analyze_file(
        self: WorkspaceAnalyzer,
        result: FileAnalysisResult,
        report: WorkspaceReport,
    ) -> None:
        if result.path.name == "bad.yar":
            raise AttributeError("parallel analyzer state missing")
        original_analyze_file(self, result, report)

    monkeypatch.setattr(WorkspaceAnalyzer, "_analyze_file", broken_analyze_file)

    with pytest.raises(AttributeError, match="parallel analyzer state missing"):
        workspace.analyze(parallel=True, max_workers=2)


def test_workspace_parallel_analysis_preserves_file_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = Workspace(str(tmp_path))
    slow_path = tmp_path / "slow.yar"
    fast_path = tmp_path / "fast.yar"

    for path, rule_name in ((slow_path, "slow"), (fast_path, "fast")):
        workspace.files[str(path)] = FileAnalysisResult(
            path=path,
            resolved=ResolvedFile(
                path=path,
                content=f"rule {rule_name} {{ condition: true }}",
                ast=YaraFile(rules=[Rule(name=rule_name, condition=BooleanLiteral(True))]),
                checksum=rule_name,
            ),
        )

    original_analyze_file = WorkspaceAnalyzer._analyze_file
    fast_finished = Event()

    def delayed_analyze_file(
        self: WorkspaceAnalyzer,
        result: FileAnalysisResult,
        report: WorkspaceReport,
    ) -> None:
        if result.path == slow_path:
            fast_finished.wait(timeout=1)
        original_analyze_file(self, result, report)
        if result.path == fast_path:
            fast_finished.set()

    monkeypatch.setattr(WorkspaceAnalyzer, "_analyze_file", delayed_analyze_file)

    report = workspace.analyze(parallel=True, max_workers=2)

    assert list(report.file_results) == list(workspace.files)


def test_workspace_analysis_rejects_invalid_worker_count(tmp_path: Path) -> None:
    workspace = Workspace(str(tmp_path))

    with pytest.raises(TypeError, match="parallel must be a boolean"):
        workspace.analyze(parallel=cast(bool, "yes"))

    with pytest.raises(TypeError, match="parallel must be a boolean"):
        WorkspaceAnalyzer(workspace).analyze(parallel=cast(bool, None))

    with pytest.raises(TypeError, match="max_workers must be an integer"):
        workspace.analyze(parallel=True, max_workers=cast(Any, True))

    with pytest.raises(ValueError, match="max_workers must be at least 1"):
        workspace.analyze(parallel=True, max_workers=0)

    analyzer = WorkspaceAnalyzer(workspace)
    report = WorkspaceReport(
        files_analyzed=0,
        total_rules=0,
        total_includes=0,
        total_imports=0,
        dependency_graph=workspace.dependency_graph,
        file_results={},
    )
    with pytest.raises(TypeError, match="max_workers must be an integer"):
        analyzer._analyze_parallel(report, max_workers=cast(Any, True))

    with pytest.raises(ValueError, match="max_workers must be at least 1"):
        analyzer._analyze_parallel(report, max_workers=0)
