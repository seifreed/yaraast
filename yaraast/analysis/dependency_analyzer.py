"""Dependency analyzer for YARA rules."""

# type: ignore  # Analysis code allows gradual typing

from collections import defaultdict

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
    StringModifier,
)
from yaraast.visitor import ASTVisitor


class DependencyAnalyzer(ASTVisitor[None]):
    """Analyze dependencies between YARA rules."""

    def __init__(self) -> None:
        self.rule_names: set[str] = set()
        self.dependencies: dict[str, set[str]] = defaultdict(
            set,
        )  # rule -> rules it depends on
        self.current_rule: str | None = None
        self.imported_modules: set[str] = set()
        self.included_files: set[str] = set()

    def analyze(self, yara_file: YaraFile) -> dict[str, any]:
        """Analyze dependencies in YARA file."""
        self.rule_names.clear()
        self.dependencies.clear()
        self.imported_modules.clear()
        self.included_files.clear()

        # First pass: collect all rule names
        for rule in yara_file.rules:
            self.rule_names.add(rule.name)

        # Visit imports and includes
        for imp in yara_file.imports:
            self.visit(imp)

        for inc in yara_file.includes:
            self.visit(inc)

        # Second pass: analyze dependencies
        for rule in yara_file.rules:
            self.visit(rule)

        return {
            "rules": list(self.rule_names),
            "dependencies": {rule: list(deps) for rule, deps in self.dependencies.items()},
            "dependency_graph": self._build_dependency_graph(),
            "circular_dependencies": self._find_circular_dependencies(),
            "dependency_order": self._topological_sort(),
            "imported_modules": list(self.imported_modules),
            "included_files": list(self.included_files),
        }

    def get_dependencies(self, rule_name: str) -> list[str]:
        """Get direct dependencies of a rule."""
        return list(self.dependencies.get(rule_name, set()))

    def get_dependents(self, rule_name: str) -> list[str]:
        """Get rules that depend on the given rule."""
        dependents = []
        for rule, deps in self.dependencies.items():
            if rule_name in deps:
                dependents.append(rule)
        return dependents

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

    def _build_dependency_graph(self) -> dict[str, dict[str, list[str]]]:
        """Build a dependency graph."""
        graph = {}

        for rule in self.rule_names:
            deps = self.dependencies.get(rule, set())
            dependents = self.get_dependents(rule)
            transitive = self.get_transitive_dependencies(rule)

            graph[rule] = {
                "depends_on": list(deps),
                "depended_by": dependents,
                "transitive_dependencies": list(transitive),
                "is_independent": len(deps) == 0 and len(dependents) == 0,
            }

        return graph

    def _find_circular_dependencies(self) -> list[list[str]]:
        """Find circular dependencies using DFS."""
        dfs_state = self._init_dfs_state()
        cycles = []

        for rule in self.rule_names:
            if dfs_state["color"][rule] == dfs_state["white"]:
                self._dfs_cycle_detection(rule, dfs_state, cycles)

        return self._remove_duplicate_cycles(cycles)

    def _init_dfs_state(self) -> dict:
        """Initialize DFS state for cycle detection."""
        white, gray, black = 0, 1, 2
        return {
            "white": white,
            "gray": gray,
            "black": black,
            "color": dict.fromkeys(self.rule_names, white),
            "path": [],
        }

    def _dfs_cycle_detection(self, node: str, state: dict, cycles: list[list[str]]) -> None:
        """Perform DFS for cycle detection."""
        state["color"][node] = state["gray"]
        state["path"].append(node)

        for neighbor in self.dependencies.get(node, set()):
            if neighbor in self.rule_names:  # Only check internal rules
                if state["color"][neighbor] == state["gray"]:
                    # Found cycle
                    cycle_start = state["path"].index(neighbor)
                    cycles.append(state["path"][cycle_start:])
                elif state["color"][neighbor] == state["white"]:
                    self._dfs_cycle_detection(neighbor, state, cycles)

        state["path"].pop()
        state["color"][node] = state["black"]

    def _remove_duplicate_cycles(self, cycles: list[list[str]]) -> list[list[str]]:
        """Remove duplicate cycles from the list."""
        unique_cycles = []
        for cycle in cycles:
            normalized = min(cycle[i:] + cycle[:i] for i in range(len(cycle)))
            if normalized not in unique_cycles:
                unique_cycles.append(normalized)

        return unique_cycles

    def _topological_sort(self) -> list[str] | None:
        """Perform topological sort on rules."""
        # Check for cycles first
        if self._find_circular_dependencies():
            return None

        in_degree = dict.fromkeys(self.rule_names, 0)

        # Calculate in-degrees: if rule A depends on rule B, then A has incoming edge from B
        for rule, deps in self.dependencies.items():
            in_degree[rule] = len([dep for dep in deps if dep in in_degree])

        # Find nodes with no incoming edges
        queue = [rule for rule, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            current = queue.pop(0)
            result.append(current)

            # Reduce in-degree for dependent nodes
            for rule, deps in self.dependencies.items():
                if current in deps and rule in in_degree:
                    in_degree[rule] -= 1
                    if in_degree[rule] == 0:
                        queue.append(rule)

        return result if len(result) == len(self.rule_names) else None

    # Visitor methods
    def visit_yara_file(self, node: YaraFile) -> None:
        for imp in node.imports:
            self.visit(imp)

        for inc in node.includes:
            self.visit(inc)

        for rule in node.rules:
            self.visit(rule)

    def visit_import(self, node: Import) -> None:
        self.imported_modules.add(node.module)

    def visit_include(self, node: Include) -> None:
        self.included_files.add(node.path)

    def visit_rule(self, node: Rule) -> None:
        self.current_rule = node.name

        # Check condition for rule references
        self.visit(node.condition)

        self.current_rule = None

    def visit_identifier(self, node: Identifier) -> None:
        # Check if identifier is a rule reference
        if self.current_rule and node.name in self.rule_names:
            self.dependencies[self.current_rule].add(node.name)

    def visit_function_call(self, node: FunctionCall) -> None:
        # Some functions might reference rules
        if node.function in self.rule_names and self.current_rule:
            self.dependencies[self.current_rule].add(node.function)

        # Visit arguments
        for arg in node.arguments:
            self.visit(arg)

    # Pass-through visitor methods
    def visit_binary_expression(self, node: BinaryExpression) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_unary_expression(self, node: UnaryExpression) -> None:
        self.visit(node.operand)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> None:
        self.visit(node.expression)

    def visit_for_expression(self, node: ForExpression) -> None:
        self.visit(node.iterable)
        self.visit(node.body)

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        self.visit(node.string_set)
        if node.condition:
            self.visit(node.condition)

    def visit_set_expression(self, node: SetExpression) -> None:
        for element in node.elements:
            self.visit(element)

    def visit_range_expression(self, node: RangeExpression) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_array_access(self, node: ArrayAccess) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_member_access(self, node: MemberAccess) -> None:
        self.visit(node.object)

    def visit_at_expression(self, node: AtExpression) -> None:
        self.visit(node.offset)

    def visit_in_expression(self, node: InExpression) -> None:
        self.visit(node.range)

    def visit_of_expression(self, node: OfExpression) -> None:
        self.visit(node.quantifier)
        self.visit(node.string_set)

    # No-op visitor methods
    def visit_tag(self, node: Tag) -> None:
        """Visit tag node - tags don't create dependencies."""

    def visit_string_definition(self, node: StringDefinition) -> None:
        """Visit string definition node - string definitions don't create dependencies."""

    def visit_plain_string(self, node: PlainString) -> None:
        """Visit plain string node - plain strings don't create dependencies."""

    def visit_hex_string(self, node: HexString) -> None:
        """Visit hex string node - hex strings don't create dependencies."""

    def visit_regex_string(self, node: RegexString) -> None:
        """Visit regex string node - regex strings don't create dependencies."""

    def visit_string_modifier(self, node: StringModifier) -> None:
        """Visit string modifier node - modifiers don't create dependencies."""

    def visit_hex_token(self, node: HexToken) -> None:
        """Visit hex token node - hex tokens don't create dependencies."""

    def visit_hex_byte(self, node: HexByte) -> None:
        """Visit hex byte node - hex bytes don't create dependencies."""

    def visit_hex_wildcard(self, node: HexWildcard) -> None:
        """Visit hex wildcard node - wildcards don't create dependencies."""

    def visit_hex_jump(self, node: HexJump) -> None:
        """Visit hex jump node - jumps don't create dependencies."""

    def visit_hex_alternative(self, node: HexAlternative) -> None:
        """Visit hex alternative node - alternatives don't create dependencies."""

    def visit_hex_nibble(self, node: HexNibble) -> None:
        """Visit hex nibble node - nibbles don't create dependencies."""

    def visit_expression(self, node: Expression) -> None:
        """Visit expression node - handled by specific expression type visitors."""

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        """Visit string identifier node - string identifiers don't create rule dependencies."""

    def visit_string_count(self, node: StringCount) -> None:
        """Visit string count node - string counts don't create dependencies."""

    def visit_string_offset(self, node: StringOffset) -> None:
        """Visit string offset node - string offsets don't create dependencies."""

    def visit_string_length(self, node: StringLength) -> None:
        """Visit string length node - string lengths don't create dependencies."""

    def visit_integer_literal(self, node: IntegerLiteral) -> None:
        """Visit integer literal node - integer literals don't create dependencies."""

    def visit_double_literal(self, node: DoubleLiteral) -> None:
        """Visit double literal node - double literals don't create dependencies."""

    def visit_string_literal(self, node: StringLiteral) -> None:
        """Visit string literal node - string literals don't create dependencies."""

    def visit_boolean_literal(self, node: BooleanLiteral) -> None:
        """Visit boolean literal node - boolean literals don't create dependencies."""

    def visit_meta(self, node: Meta) -> None:
        """Visit meta node - meta fields don't create dependencies."""

    def visit_meta_statement(self, node) -> None:
        """Visit meta statement node - meta statements don't create dependencies."""

    def visit_condition(self, node) -> None:
        """Visit condition node - handled by specific condition visitors."""

    def visit_comment(self, node) -> None:
        """Visit comment node - comments don't create dependencies."""

    def visit_comment_group(self, node) -> None:
        """Visit comment group node - comment groups don't create dependencies."""

    def visit_module_reference(self, node) -> None:
        """Visit module reference node - module references are handled by imports."""

    def visit_dictionary_access(self, node) -> None:
        """Visit dictionary access node - dictionary access doesn't create rule dependencies."""

    def visit_defined_expression(self, node) -> None:
        """Visit defined expression node - defined expressions don't create rule dependencies."""

    def visit_string_operator_expression(self, node) -> None:
        """Visit string operator expression node - string operators don't create rule dependencies."""

    # Add missing abstract methods
    def visit_extern_import(self, node) -> None:
        """Visit extern import node - extern imports don't create rule dependencies."""

    def visit_extern_namespace(self, node) -> None:
        """Visit extern namespace node - extern namespaces don't create rule dependencies."""

    def visit_extern_rule(self, node) -> None:
        """Visit extern rule node - extern rules are handled separately from internal rules."""

    def visit_extern_rule_reference(self, node) -> None:
        """Visit extern rule reference node - extern rule references are handled separately."""

    def visit_in_rule_pragma(self, node) -> None:
        """Visit in-rule pragma node - pragmas don't create dependencies."""

    def visit_pragma(self, node) -> None:
        """Visit pragma node - pragmas don't create dependencies."""

    def visit_pragma_block(self, node) -> None:
        """Visit pragma block node - pragma blocks don't create dependencies."""

    def visit_regex_literal(self, node) -> None:
        """Visit regex literal node - regex literals don't create dependencies."""
