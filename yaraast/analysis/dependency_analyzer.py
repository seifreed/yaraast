"""Dependency analyzer for YARA rules."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any, TypedDict

from yaraast.ast.base import ASTNode
from yaraast.ast.expressions import Identifier, StringWildcard
from yaraast.visitor.base import BaseVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.conditions import ForExpression
    from yaraast.ast.expressions import FunctionCall
    from yaraast.ast.rules import Import, Include, Rule
    from yaraast.yarax.ast_nodes import (
        ArrayComprehension,
        DictComprehension,
        LambdaExpression,
        WithDeclaration,
        WithStatement,
    )


class DependencyGraphEntry(TypedDict):
    """Per-rule dependency graph details."""

    depends_on: list[str]
    depended_by: list[str]
    transitive_dependencies: list[str]
    is_independent: bool


class DependencyAnalyzer(BaseVisitor[None]):
    """Analyze dependencies between YARA rules."""

    def __init__(self) -> None:
        self.rule_names: set[str] = set()
        self.dependencies: dict[str, set[str]] = defaultdict(
            set,
        )  # rule -> rules it depends on
        self.current_rule: str | None = None
        self.current_rule_key: str | None = None
        self.imported_modules: set[str] = set()
        self.included_files: set[str] = set()
        self.local_scopes: list[set[str]] = []
        self._raw_rule_names: set[str] = set()
        self._rule_keys_by_id: dict[int, str] = {}
        self._rule_keys_by_name: dict[str, list[str]] = {}

    def analyze(self, yara_file: YaraFile) -> dict[str, Any]:
        """Analyze dependencies in YARA file."""
        self.rule_names.clear()
        self.dependencies.clear()
        self.imported_modules.clear()
        self.included_files.clear()
        self.current_rule = None
        self.current_rule_key = None
        self.local_scopes.clear()
        self._raw_rule_names.clear()
        self._rule_keys_by_id.clear()
        self._rule_keys_by_name.clear()

        # First pass: collect all rule names
        self._raw_rule_names = {rule.name for rule in yara_file.rules}
        rule_counts = Counter(rule.name for rule in yara_file.rules)
        seen_rules: defaultdict[str, int] = defaultdict(int)
        for rule in yara_file.rules:
            seen_rules[rule.name] += 1
            rule_key = self._rule_analysis_key(
                rule.name,
                seen_rules[rule.name],
                rule_counts,
            )
            self.rule_names.add(rule_key)
            self._rule_keys_by_id[id(rule)] = rule_key
            self._rule_keys_by_name.setdefault(rule.name, []).append(rule_key)

        # Visit imports and includes
        for imp in yara_file.imports:
            self.visit(imp)

        for inc in yara_file.includes:
            self.visit(inc)

        # Second pass: analyze dependencies
        for rule in yara_file.rules:
            self.visit(rule)

        return {
            "rules": sorted(self.rule_names),
            "dependencies": {
                rule: sorted(deps) for rule, deps in sorted(self.dependencies.items())
            },
            "dependency_graph": self._build_dependency_graph(),
            "circular_dependencies": self._find_circular_dependencies(),
            "dependency_order": self._topological_sort(),
            "imported_modules": sorted(self.imported_modules),
            "included_files": sorted(self.included_files),
        }

    def get_dependencies(self, rule_name: str) -> list[str]:
        """Get direct dependencies of a rule."""
        return sorted(self.dependencies.get(rule_name, set()))

    def get_dependents(self, rule_name: str) -> list[str]:
        """Get rules that depend on the given rule."""
        dependents = []
        for rule, deps in self.dependencies.items():
            if rule_name in deps:
                dependents.append(rule)
        return sorted(dependents)

    def get_transitive_dependencies(self, rule_name: str) -> set[str]:
        """Get all transitive dependencies of a rule."""
        visited = set()
        to_visit = [rule_name]

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue

            visited.add(current)
            deps = self.dependencies.get(current, set())
            to_visit.extend(deps - visited)

        visited.remove(rule_name)  # Don't include self
        return visited

    def _build_dependency_graph(self) -> dict[str, DependencyGraphEntry]:
        """Build a dependency graph."""
        graph: dict[str, DependencyGraphEntry] = {}

        for rule in sorted(self.rule_names):
            deps = self.dependencies.get(rule, set())
            dependents = self.get_dependents(rule)
            transitive = self.get_transitive_dependencies(rule)

            graph[rule] = {
                "depends_on": sorted(deps),
                "depended_by": dependents,
                "transitive_dependencies": sorted(transitive),
                "is_independent": len(deps) == 0 and len(dependents) == 0,
            }

        return graph

    def _find_circular_dependencies(self) -> list[list[str]]:
        """Find circular dependencies using DFS."""
        dfs_state = self._init_dfs_state()
        cycles = []

        for rule in sorted(self.rule_names):
            if dfs_state["color"][rule] == dfs_state["white"]:
                self._dfs_cycle_detection(rule, dfs_state, cycles)

        return self._remove_duplicate_cycles(cycles)

    def _init_dfs_state(self) -> dict[str, Any]:
        """Initialize DFS state for cycle detection."""
        white, gray, black = 0, 1, 2
        return {
            "white": white,
            "gray": gray,
            "black": black,
            "color": dict.fromkeys(self.rule_names, white),
            "path": [],
        }

    def _dfs_cycle_detection(
        self, node: str, state: dict[str, Any], cycles: list[list[str]]
    ) -> None:
        """Perform DFS for cycle detection."""
        state["color"][node] = state["gray"]
        state["path"].append(node)

        for neighbor in sorted(self.dependencies.get(node, set())):
            if neighbor in self.rule_names:  # Only check internal rules
                if state["color"][neighbor] == state["gray"]:
                    # Found cycle - include the back-edge to close it
                    cycle_start = state["path"].index(neighbor)
                    cycles.append([*state["path"][cycle_start:], neighbor])
                elif state["color"][neighbor] == state["white"]:
                    self._dfs_cycle_detection(neighbor, state, cycles)

        state["path"].pop()
        state["color"][node] = state["black"]

    def _remove_duplicate_cycles(self, cycles: list[list[str]]) -> list[list[str]]:
        """Remove duplicate cycles from the list."""
        unique_cycles = []
        for cycle in cycles:
            # Normalize by rotating the cycle body (excluding closing back-edge)
            body = cycle[:-1] if len(cycle) > 1 and cycle[0] == cycle[-1] else cycle
            if body:
                normalized_body = min(body[i:] + body[:i] for i in range(len(body)))
                normalized = [*normalized_body, normalized_body[0]]  # Re-add closing edge
            else:
                normalized = cycle
            if normalized not in unique_cycles:
                unique_cycles.append(normalized)

        return unique_cycles

    def _topological_sort(self) -> list[str] | None:
        """Perform topological sort on rules."""
        # Check for cycles first
        if self._find_circular_dependencies():
            return None

        in_degree = dict.fromkeys(sorted(self.rule_names), 0)

        # Calculate in-degrees: if rule A depends on rule B, then A has incoming edge from B
        for rule, deps in sorted(self.dependencies.items()):
            in_degree[rule] = len([dep for dep in deps if dep in in_degree])

        # Find nodes with no incoming edges
        queue = [rule for rule, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            current = queue.pop(0)
            result.append(current)

            # Reduce in-degree for dependent nodes
            for rule, deps in sorted(self.dependencies.items()):
                if current in deps and rule in in_degree:
                    in_degree[rule] -= 1
                    if in_degree[rule] == 0:
                        queue.append(rule)

        return result if len(result) == len(self.rule_names) else None

    # Visitor methods with actual logic
    def visit_import(self, node: Import) -> None:
        self.imported_modules.add(node.module)

    def visit_include(self, node: Include) -> None:
        self.included_files.add(node.path)

    def visit_rule(self, node: Rule) -> None:
        self.current_rule = node.name
        self.current_rule_key = self._analysis_key_for_rule(node)

        # Check condition for rule references
        try:
            if node.condition:
                self.visit(node.condition)
        finally:
            self.current_rule = None
            self.current_rule_key = None

    def _rule_analysis_key(
        self,
        rule_name: str,
        occurrence: int,
        counts: Counter[str],
    ) -> str:
        if counts[rule_name] == 1:
            return rule_name
        return f"{rule_name}#{occurrence}"

    def _analysis_key_for_rule(self, rule: Rule) -> str:
        return self._rule_keys_by_id.get(id(rule), rule.name)

    def _active_rule_key(self) -> str | None:
        return self.current_rule_key or self.current_rule

    def _known_raw_rule_names(self) -> set[str]:
        return self._raw_rule_names or self.rule_names

    def _dependency_targets_for_rule_name(self, rule_name: str) -> tuple[str, ...]:
        rule_keys = self._rule_keys_by_name.get(rule_name)
        if not rule_keys:
            return (rule_name,)
        return tuple(rule_keys)

    def visit_identifier(self, node: Identifier) -> None:
        # Check if identifier is a rule reference
        rule_key = self._active_rule_key()
        if (
            rule_key
            and self.current_rule
            and node.name in self._known_raw_rule_names()
            and node.name != self.current_rule
            and not self._is_local(node.name)
        ):
            self.dependencies[rule_key].update(self._dependency_targets_for_rule_name(node.name))

    def visit_string_wildcard(self, node: StringWildcard) -> None:
        if node.pattern.startswith("$"):
            return

        rule_key = self._active_rule_key()
        if not rule_key:
            return

        for rule_name in self._matching_rule_wildcard_names(node.pattern):
            self.dependencies[rule_key].update(self._dependency_targets_for_rule_name(rule_name))

    def _matching_rule_wildcard_names(self, pattern: str) -> tuple[str, ...]:
        if not pattern.endswith("*"):
            return ()
        prefix = pattern[:-1]
        if not prefix:
            return ()
        return tuple(
            sorted(
                rule_name
                for rule_name in self._known_raw_rule_names()
                if rule_name.startswith(prefix)
                and rule_name != self.current_rule
                and not self._is_local(rule_name)
            )
        )

    def visit_function_call(self, node: FunctionCall) -> None:
        # Function callees are not rule references; only their arguments can contain them.
        super().visit_function_call(node)

    def visit_member_access(self, node) -> None:
        # Member roots are modules/objects, not bare rule references.
        if not isinstance(node.object, Identifier):
            self.visit(node.object)

    def visit_for_expression(self, node: ForExpression) -> None:
        if isinstance(node.quantifier, ASTNode):
            self.visit(node.quantifier)
        self.visit(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_statement(self, node: WithStatement) -> None:
        self._push_local_scope()
        try:
            for declaration in node.declarations:
                self.visit(declaration)
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_declaration(self, node: WithDeclaration) -> None:
        self.visit(node.value)
        self._define_local(node.identifier)

    def visit_array_comprehension(self, node: ArrayComprehension) -> None:
        self._visit_if(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self._visit_if(node.condition)
            self._visit_if(node.expression)
        finally:
            self._pop_local_scope()

    def visit_dict_comprehension(self, node: DictComprehension) -> None:
        self._visit_if(node.iterable)
        names = [node.key_variable]
        if node.value_variable:
            names.append(node.value_variable)
        self._push_local_scope(*names)
        try:
            self._visit_if(node.condition)
            self._visit_if(node.key_expression)
            self._visit_if(node.value_expression)
        finally:
            self._pop_local_scope()

    def visit_lambda_expression(self, node: LambdaExpression) -> None:
        self._push_local_scope(*node.parameters)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def _is_local(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self.local_scopes))

    def _push_local_scope(self, *names: str) -> None:
        scope: set[str] = set()
        for name in names:
            scope.update(self._local_name_variants(name))
        self.local_scopes.append(scope)

    def _pop_local_scope(self) -> None:
        self.local_scopes.pop()

    def _define_local(self, name: str) -> None:
        if self.local_scopes:
            self.local_scopes[-1].update(self._local_name_variants(name))

    @staticmethod
    def _local_name_variants(name: str) -> set[str]:
        names = [part.strip() for part in name.split(",")]
        return {local_name for local_name in names if local_name}
