"""Dependency graph for YARA files and rules."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.errors import ValidationError
from yaraast.metrics.dependency_graph_finder import DependencyFinder

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


def _require_path(value: object, context: str) -> Path:
    if isinstance(value, Path):
        if not str(value).strip():
            msg = f"{context} must not be empty"
            raise ValidationError(msg)
        return value
    if isinstance(value, str):
        if not value.strip():
            msg = f"{context} must not be empty"
            raise ValidationError(msg)
        return Path(value)
    msg = f"{context} must be a path"
    raise ValidationError(msg)


def _require_query_path(value: object, context: str) -> Path:
    return _require_path(value, context)


def _require_string(value: object, context: str) -> str:
    if isinstance(value, str):
        if not value.strip():
            msg = f"{context} must not be empty"
            raise ValidationError(msg)
        return value
    msg = f"{context} must be a string"
    raise ValidationError(msg)


def require_rule_lookup_name(value: object) -> str:
    return _require_string(value, "DependencyGraph rule name")


def _require_string_or_path(value: object, context: str) -> str | Path:
    if isinstance(value, str):
        if not value.strip():
            msg = f"{context} must not be empty"
            raise ValidationError(msg)
        return value
    if isinstance(value, Path):
        if not str(value).strip():
            msg = f"{context} must not be empty"
            raise ValidationError(msg)
        return value
    msg = f"{context} must be a string or path"
    raise ValidationError(msg)


def _require_yara_file(value: object) -> YaraFile:
    from yaraast.ast.base import YaraFile

    if isinstance(value, YaraFile):
        return value
    msg = "DependencyGraph ast must be a YaraFile"
    raise ValidationError(msg)


def _normalize_include_resolutions(value: object) -> dict[str, str | Path]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        msg = "DependencyGraph include resolutions must be a mapping"
        raise ValidationError(msg)

    resolutions: dict[str, str | Path] = {}
    for include_path, resolved_path in value.items():
        key = _require_string(include_path, "DependencyGraph include resolution key")
        resolutions[key] = _require_string_or_path(
            resolved_path,
            "DependencyGraph include resolution value",
        )
    return resolutions


def _module_name_for_object(value: object) -> str | None:
    module = getattr(value, "module", None)
    if isinstance(module, str):
        return module
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return None


class _RuleDependencyCollector(DependencyFinder):
    """Collect rule and imported-module references from one rule condition."""

    def __init__(
        self,
        current_rule: str,
        rule_names: set[str],
        module_aliases: Mapping[str, str],
    ) -> None:
        super().__init__(current_rule, rule_names)
        self.module_aliases = module_aliases
        self.module_references: set[str] = set()

    def visit_function_call(self, node: Any) -> None:
        function_name = getattr(node, "function", "")
        module_name = function_name.split(".", 1)[0] if "." in function_name else None
        self._add_module_reference(module_name)
        super().visit_function_call(node)

    def visit_member_access(self, node: Any) -> None:
        module_name = _module_name_for_object(node.object)
        self._add_module_reference(module_name)
        super().visit_member_access(node)

    def visit_module_reference(self, node: Any) -> None:
        module_name = getattr(node, "module", None)
        self._add_module_reference(module_name)

    def _add_module_reference(self, module_name: object) -> None:
        if not isinstance(module_name, str) or self._is_local(module_name):
            return
        canonical_name = self.module_aliases.get(module_name)
        if canonical_name:
            self.module_references.add(canonical_name)


def _rule_occurrence_keys(rules: list[Rule]) -> dict[int, str]:
    counts = Counter(rule.name for rule in rules)
    seen_rules: defaultdict[str, int] = defaultdict(int)
    rule_keys: dict[int, str] = {}

    for rule in rules:
        seen_rules[rule.name] += 1
        rule_keys[id(rule)] = _rule_occurrence_key(
            rule.name,
            seen_rules[rule.name],
            counts,
        )

    return rule_keys


def _rule_occurrence_key(rule_name: str, occurrence: int, counts: Counter[str]) -> str:
    if counts[rule_name] == 1:
        return rule_name
    return f"{rule_name}#{occurrence}"


@dataclass
class DependencyNode:
    """Node in the dependency graph."""

    name: str
    type: str  # 'file', 'rule', 'module'
    file_path: Path | None = None
    dependencies: set[str] = field(default_factory=set)
    dependents: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)


class DependencyGraph:
    """Build and analyze dependency graphs for YARA files."""

    def __init__(self) -> None:
        self.nodes: dict[str, DependencyNode] = {}
        self.file_rules: dict[str, set[str]] = {}  # file_path -> rule occurrence names
        self.rule_files: dict[str, str] = {}  # rule occurrence name -> file_path
        # rule_key -> (rule AST, module aliases) for re-analysis once all rule
        # nodes across every file are present.
        self._rule_analysis_inputs: dict[str, tuple[Rule, dict[str, str]]] = {}

    def add_file(
        self,
        file_path: Path,
        ast: YaraFile,
        include_resolutions: Mapping[str, str | Path] | None = None,
    ) -> None:
        """Add a YARA file to the dependency graph."""
        file_path = _require_path(file_path, "DependencyGraph file_path")
        ast = _require_yara_file(ast)
        include_resolutions = _normalize_include_resolutions(include_resolutions)
        self._validate_file_ast(ast)

        file_key = str(file_path)

        self._remove_existing_file_state(file_key)

        # Add file node
        if file_key not in self.nodes:
            self.nodes[file_key] = DependencyNode(
                name=file_key,
                type="file",
                file_path=file_path,
            )
        else:
            self.nodes[file_key].type = "file"
            self.nodes[file_key].file_path = file_path

        # Track rules in this file
        self.file_rules[file_key] = set()

        # Add imports as dependencies
        module_aliases: dict[str, str] = {}
        for import_stmt in ast.imports:
            module_name = import_stmt.module
            self._add_module_dependency(file_key, module_name)
            module_aliases[module_name] = module_name
            if import_stmt.alias:
                module_aliases[import_stmt.alias] = module_name

        # Add includes as dependencies
        for include_stmt in ast.includes:
            include_target = include_resolutions.get(include_stmt.path, include_stmt.path)
            self._add_include_dependency(file_key, include_target)

        # Add all rules first so forward references can resolve during analysis.
        rule_keys = _rule_occurrence_keys(ast.rules)
        for rule in ast.rules:
            rule_key = f"rule:{rule_keys[id(rule)]}"
            self._add_rule(file_key, rule, rule_keys[id(rule)])
            self._rule_analysis_inputs[rule_key] = (rule, dict(module_aliases))

        # Re-analyze every known rule so cross-file references resolve regardless
        # of the order files are added and survive re-adding included files.
        self._reanalyze_all_rules()

    def _reanalyze_all_rules(self) -> None:
        """Recompute rule dependency edges for every rule node in the graph."""
        for rule_key, (rule, module_aliases) in self._rule_analysis_inputs.items():
            if rule_key in self.nodes:
                self._analyze_rule_dependencies(rule_key, rule, module_aliases)

    def _validate_file_ast(self, ast: YaraFile) -> None:
        """Validate graph-relevant AST fields before mutating graph state."""
        from yaraast.ast.rules import Import, Include, Rule, Tag

        for import_stmt in ast.imports:
            if not isinstance(import_stmt, Import):
                msg = "DependencyGraph imports must contain Import nodes"
                raise ValidationError(msg)
            _require_string(import_stmt.module, "DependencyGraph import module")
            if import_stmt.alias is not None:
                _require_string(import_stmt.alias, "DependencyGraph import alias")

        for include_stmt in ast.includes:
            if not isinstance(include_stmt, Include):
                msg = "DependencyGraph includes must contain Include nodes"
                raise ValidationError(msg)
            _require_string_or_path(include_stmt.path, "DependencyGraph include path")

        for rule in ast.rules:
            if not isinstance(rule, Rule):
                msg = "DependencyGraph rules must contain Rule nodes"
                raise ValidationError(msg)
            _require_string(rule.name, "DependencyGraph rule name")
            for tag in getattr(rule, "tags", []):
                if not isinstance(tag, Tag):
                    msg = "DependencyGraph rule tags must contain Tag nodes"
                    raise ValidationError(msg)
                _require_string(tag.name, "DependencyGraph tag name")

    def _remove_existing_file_state(self, file_key: str) -> None:
        """Remove stale graph state before re-adding a file."""
        file_node = self.nodes.get(file_key)
        if file_node is not None:
            for dependency in list(file_node.dependencies):
                dependency_node = self.nodes.get(dependency)
                if dependency_node is not None:
                    dependency_node.dependents.discard(file_key)
                    self._remove_orphan_external_node(dependency)
            file_node.dependencies.clear()

        for rule_name in self.file_rules.get(file_key, set()).copy():
            rule_key = f"rule:{rule_name}"
            rule_node = self.nodes.get(rule_key)
            if rule_node is not None and str(rule_node.file_path) == file_key:
                self._remove_rule_node(rule_key)
            if self.rule_files.get(rule_name) == file_key:
                del self.rule_files[rule_name]

        self.file_rules.pop(file_key, None)

    def _remove_rule_node(self, rule_key: str) -> None:
        """Remove a rule node and references to it."""
        self._rule_analysis_inputs.pop(rule_key, None)
        rule_node = self.nodes.pop(rule_key, None)
        if rule_node is None:
            return

        for dependency in list(rule_node.dependencies):
            dependency_node = self.nodes.get(dependency)
            if dependency_node is not None:
                dependency_node.dependents.discard(rule_key)
                self._remove_orphan_external_node(dependency)

        for dependent in list(rule_node.dependents):
            dependent_node = self.nodes.get(dependent)
            if dependent_node is not None:
                dependent_node.dependencies.discard(rule_key)

    def _remove_orphan_external_node(self, node_key: str) -> None:
        """Remove include/module placeholders that no node references anymore."""
        node = self.nodes.get(node_key)
        if node is not None and node.type in {"include", "module"} and not node.dependents:
            self.nodes.pop(node_key, None)

    def _add_module_dependency(self, file_key: str, module_name: str) -> None:
        """Add module dependency."""
        # Create module node if not exists
        if module_name not in self.nodes:
            self.nodes[module_name] = DependencyNode(name=module_name, type="module")

        # Add dependency
        self.nodes[file_key].dependencies.add(module_name)
        self.nodes[module_name].dependents.add(file_key)

    def _add_include_dependency(self, file_key: str, include_path: str | Path) -> None:
        """Add include dependency."""
        include_key = str(include_path)
        if include_key not in self.nodes:
            self.nodes[include_key] = DependencyNode(name=include_key, type="include")
        self.nodes[file_key].dependencies.add(include_key)
        self.nodes[include_key].dependents.add(file_key)

    def _add_rule(self, file_key: str, rule: Rule, rule_name: str) -> None:
        """Add rule to the graph and analyze its dependencies."""
        rule_key = f"rule:{rule_name}"

        # Create rule node
        self.nodes[rule_key] = DependencyNode(
            name=rule.name,
            type="rule",
            file_path=Path(file_key),
            metadata={
                "modifiers": rule.modifiers,
                "tags": ([tag.name for tag in rule.tags] if hasattr(rule, "tags") else []),
            },
        )

        # Track rule location
        self.file_rules[file_key].add(rule_name)
        self.rule_files[rule_name] = file_key

        # File depends on rule
        self.nodes[file_key].dependencies.add(rule_key)
        self.nodes[rule_key].dependents.add(file_key)

    def _analyze_rule_dependencies(
        self,
        rule_key: str,
        rule: Rule,
        module_aliases: Mapping[str, str],
    ) -> None:
        """Analyze dependencies within a rule."""
        if rule.condition is None:
            return

        collector = _RuleDependencyCollector(
            rule.name,
            self._raw_rule_names(),
            module_aliases,
        )
        collector.visit(rule.condition)

        for dependency_name in sorted(collector.dependencies):
            for dependency_key in self._rule_node_keys_for_name(dependency_name):
                if dependency_key != rule_key:
                    self._add_dependency_edge(rule_key, dependency_key)

        for module_name in sorted(collector.module_references):
            self._add_dependency_edge(rule_key, module_name)

    def _raw_rule_names(self) -> set[str]:
        return {node.name for node in self.nodes.values() if node.type == "rule"}

    def _rule_node_keys_for_name(self, rule_name: str) -> list[str]:
        return [
            node_key
            for node_key, node in sorted(self.nodes.items())
            if node.type == "rule" and node.name == rule_name
        ]

    def _add_dependency_edge(self, from_key: str, to_key: str) -> None:
        if from_key not in self.nodes or to_key not in self.nodes:
            return
        self.nodes[from_key].dependencies.add(to_key)
        self.nodes[to_key].dependents.add(from_key)

    def get_file_dependencies(self, file_path: object) -> set[str]:
        """Get all dependencies of a file (transitive)."""
        query_path = _require_query_path(file_path, "DependencyGraph file_path")

        # Resolve path to handle symlinks (e.g., /var -> /private/var on macOS)
        resolved_path = str(query_path.resolve())

        # Try both resolved and original paths
        if resolved_path in self.nodes:
            return self._get_transitive_dependencies(resolved_path)
        return self._get_transitive_dependencies(str(query_path))

    def get_file_dependents(self, file_path: object) -> set[str]:
        """Get all files that depend on this file (transitive)."""
        query_path = _require_query_path(file_path, "DependencyGraph file_path")
        resolved_path = str(query_path.resolve())
        if resolved_path in self.nodes:
            return self._get_transitive_dependents(resolved_path)
        return self._get_transitive_dependents(str(query_path))

    def get_rule_dependencies(self, rule_name: str) -> set[str]:
        """Get all dependencies of a rule."""
        rule_name = require_rule_lookup_name(rule_name)
        rule_key = f"rule:{rule_name}"
        if rule_key not in self.nodes:
            return set()
        return self.nodes[rule_key].dependencies.copy()

    def _get_transitive_dependencies(self, node_key: str) -> set[str]:
        """Get transitive dependencies of a node."""
        if node_key not in self.nodes:
            return set()

        visited = set()
        to_visit = [node_key]
        dependencies = set()

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue

            visited.add(current)
            node = self.nodes.get(current)
            if node is not None:
                dependencies.update(node.dependencies)
                to_visit.extend(node.dependencies)

        dependencies.discard(node_key)
        return dependencies

    def _get_transitive_dependents(self, node_key: str) -> set[str]:
        """Get transitive dependents of a node."""
        if node_key not in self.nodes:
            return set()

        visited = set()
        to_visit = [node_key]
        dependents = set()

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue

            visited.add(current)
            node = self.nodes.get(current)
            if node is not None:
                dependents.update(node.dependents)
                to_visit.extend(node.dependents)

        dependents.discard(node_key)
        return dependents

    def find_cycles(self) -> list[list[str]]:
        """Find dependency cycles in the graph."""
        cycles: list[list[str]] = []
        visited: set[str] = set()
        active: set[str] = set()
        path: list[str] = []

        def add_cycle(cycle: list[str]) -> None:
            body = cycle[:-1]
            if not body:
                return
            min_idx = body.index(min(body))
            rotated = body[min_idx:] + body[:min_idx]
            normalized = [*rotated, rotated[0]]
            if normalized not in cycles:
                cycles.append(normalized)

        def dfs(node_key: str) -> None:
            visited.add(node_key)
            active.add(node_key)
            path.append(node_key)

            for dependency in sorted(self.nodes[node_key].dependencies):
                if dependency not in self.nodes:
                    continue
                if dependency not in visited:
                    dfs(dependency)
                elif dependency in active:
                    cycle_start = path.index(dependency)
                    add_cycle([*path[cycle_start:], dependency])

            path.pop()
            active.remove(node_key)

        for node_key in sorted(self.nodes):
            if node_key not in visited:
                dfs(node_key)

        return cycles

    def get_isolated_nodes(self) -> set[str]:
        """Get nodes with no dependencies or dependents."""
        isolated = set()
        for node_key, node in self.nodes.items():
            if not node.dependencies and not node.dependents:
                isolated.add(node_key)
        return isolated

    def get_statistics(self) -> dict[str, int]:
        """Get graph statistics."""
        file_nodes = [n for n in self.nodes.values() if n.type == "file"]
        rule_nodes = [n for n in self.nodes.values() if n.type == "rule"]
        module_nodes = [n for n in self.nodes.values() if n.type == "module"]

        return {
            "total_nodes": len(self.nodes),
            "file_count": len(file_nodes),
            "rule_count": len(rule_nodes),
            "module_count": len(module_nodes),
            "total_edges": sum(len(n.dependencies) for n in self.nodes.values()),
            "isolated_nodes": len(self.get_isolated_nodes()),
            "cycles": len(self.find_cycles()),
        }

    def export_dot(self) -> str:
        """Export graph to DOT format for visualization."""
        lines = ["digraph YaraDependencies {"]
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box];")

        # Style nodes by type
        for node_key, node in sorted(self.nodes.items()):
            label = node.name
            if node.type == "file":
                style = "shape=folder,style=filled,fillcolor=lightblue"
            elif node.type == "rule":
                style = "shape=box,style=filled,fillcolor=lightgreen"
            elif node.type == "module":
                style = "shape=component,style=filled,fillcolor=lightyellow"
            else:
                style = ""

            # Escape special characters
            safe_key = node_key.replace('"', '\\"').replace(":", "_")
            safe_label = label.replace('"', '\\"')

            lines.append(f'  "{safe_key}" [label="{safe_label}",{style}];')

        # Add edges
        for node_key, node in sorted(self.nodes.items()):
            safe_key = node_key.replace('"', '\\"').replace(":", "_")
            for dep in sorted(node.dependencies):
                safe_dep = dep.replace('"', '\\"').replace(":", "_")
                lines.append(f'  "{safe_key}" -> "{safe_dep}";')

        lines.append("}")
        return "\n".join(lines)
