"""AST diff functionality for incremental versioning."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile


class DiffType(Enum):
    """Type of difference between AST nodes."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    MOVED = "moved"


@dataclass
class DiffNode:
    """Represents a difference in the AST."""

    path: str  # XPath-like path to the node
    diff_type: DiffType
    old_value: Any | None = None
    new_value: Any | None = None
    node_type: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiffResult:
    """Result of AST comparison."""

    old_ast_hash: str
    new_ast_hash: str
    differences: list[DiffNode] = field(default_factory=list)
    statistics: dict[str, int] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return len(self.differences) > 0

    @property
    def change_summary(self) -> dict[str, int]:
        """Get summary of changes by type."""
        summary = {diff_type.value: 0 for diff_type in DiffType}
        for diff in self.differences:
            summary[diff.diff_type.value] += 1
        return summary

    def get_changes_by_type(self, diff_type: DiffType) -> list[DiffNode]:
        """Get all changes of a specific type."""
        return [diff for diff in self.differences if diff.diff_type == diff_type]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "old_ast_hash": self.old_ast_hash,
            "new_ast_hash": self.new_ast_hash,
            "has_changes": self.has_changes,
            "change_summary": self.change_summary,
            "differences": [
                {
                    "path": diff.path,
                    "type": diff.diff_type.value,
                    "old_value": diff.old_value,
                    "new_value": diff.new_value,
                    "node_type": diff.node_type,
                    "details": diff.details,
                }
                for diff in self.differences
            ],
            "statistics": self.statistics,
        }


class AstHasher(ASTVisitor[str]):
    """Creates structural hashes of AST nodes."""

    def __init__(self) -> None:
        self._node_hashes: dict[str, str] = {}

    def hash_ast(self, ast: YaraFile) -> str:
        """Create a hash of the entire AST."""
        ast_repr = self.visit(ast)
        return hashlib.sha256(ast_repr.encode()).hexdigest()[:16]

    def hash_node(self, node: ASTNode, path: str = "") -> str:
        """Create a hash of a specific node."""
        node_repr = self.visit(node)
        node_hash = hashlib.sha256(f"{path}:{node_repr}".encode()).hexdigest()[:12]
        self._node_hashes[path] = node_hash
        return node_hash

    def visit_yara_file(self, node: YaraFile) -> str:
        """Hash YaraFile node."""
        imports_hash = "|".join(self.visit(imp) for imp in node.imports)
        includes_hash = "|".join(self.visit(inc) for inc in node.includes)
        rules_hash = "|".join(self.visit(rule) for rule in node.rules)
        return f"YaraFile({imports_hash}|{includes_hash}|{rules_hash})"

    def visit_import(self, node) -> str:
        """Hash Import node."""
        alias = getattr(node, "alias", None)
        return f"Import({node.module},{alias})"

    def visit_include(self, node) -> str:
        """Hash Include node."""
        return f"Include({node.path})"

    def visit_rule(self, node) -> str:
        """Hash Rule node."""
        modifiers = "|".join(sorted(node.modifiers))
        tags = "|".join(self.visit(tag) for tag in node.tags)
        meta = "|".join(f"{k}:{v}" for k, v in sorted(node.meta.items()))
        strings = "|".join(self.visit(s) for s in node.strings)
        condition = self.visit(node.condition) if node.condition else ""
        return f"Rule({node.name},{modifiers},{tags},{meta},{strings},{condition})"

    def visit_tag(self, node) -> str:
        """Hash Tag node."""
        return f"Tag({node.name})"

    def visit_plain_string(self, node) -> str:
        """Hash PlainString node."""
        modifiers = "|".join(self.visit(mod) for mod in node.modifiers)
        return f"PlainString({node.identifier},{node.value},{modifiers})"

    def visit_hex_string(self, node) -> str:
        """Hash HexString node."""
        tokens = "|".join(self.visit(token) for token in node.tokens)
        modifiers = "|".join(self.visit(mod) for mod in node.modifiers)
        return f"HexString({node.identifier},{tokens},{modifiers})"

    def visit_regex_string(self, node) -> str:
        """Hash RegexString node."""
        modifiers = "|".join(self.visit(mod) for mod in node.modifiers)
        return f"RegexString({node.identifier},{node.regex},{modifiers})"

    def visit_string_modifier(self, node) -> str:
        """Hash StringModifier node."""
        return f"Mod({node.name},{node.value})"

    def visit_hex_byte(self, node) -> str:
        """Hash HexByte node."""
        return f"Byte({node.value})"

    def visit_hex_wildcard(self, node) -> str:
        """Hash HexWildcard node."""
        return "Wildcard()"

    def visit_hex_jump(self, node) -> str:
        """Hash HexJump node."""
        return f"Jump({node.min_jump},{node.max_jump})"

    def visit_binary_expression(self, node) -> str:
        """Hash BinaryExpression node."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        return f"Binary({left},{node.operator},{right})"

    def visit_identifier(self, node) -> str:
        """Hash Identifier node."""
        return f"Id({node.name})"

    def visit_string_identifier(self, node) -> str:
        """Hash StringIdentifier node."""
        return f"StrId({node.name})"

    def visit_integer_literal(self, node) -> str:
        """Hash IntegerLiteral node."""
        return f"Int({node.value})"

    def visit_boolean_literal(self, node) -> str:
        """Hash BooleanLiteral node."""
        return f"Bool({node.value})"

    # Default implementations for other visitor methods
    def visit_string_definition(self, node) -> str:
        return f"StringDef({node.identifier})"

    def visit_hex_token(self, node) -> str:
        return "Token()"

    def visit_hex_alternative(self, node) -> str:
        return "Alt()"

    def visit_hex_nibble(self, node) -> str:
        return f"Nibble({node.high},{node.value})"

    def visit_expression(self, node) -> str:
        return "Expr()"

    def visit_string_count(self, node) -> str:
        return f"Count({node.string_id})"

    def visit_string_offset(self, node) -> str:
        return f"Offset({node.string_id})"

    def visit_string_length(self, node) -> str:
        return f"Length({node.string_id})"

    def visit_double_literal(self, node) -> str:
        return f"Double({node.value})"

    def visit_string_literal(self, node) -> str:
        return f"Str({node.value})"

    def visit_regex_literal(self, node) -> str:
        return f"Regex({node.pattern},{node.modifiers})"

    def visit_unary_expression(self, node) -> str:
        return f"Unary({node.operator},{self.visit(node.operand)})"

    def visit_parentheses_expression(self, node) -> str:
        return f"Parens({self.visit(node.expression)})"

    def visit_set_expression(self, node) -> str:
        elements = "|".join(self.visit(elem) for elem in node.elements)
        return f"Set({elements})"

    def visit_range_expression(self, node) -> str:
        return f"Range({self.visit(node.low)},{self.visit(node.high)})"

    def visit_function_call(self, node) -> str:
        args = "|".join(self.visit(arg) for arg in node.arguments)
        return f"Call({node.function},{args})"

    def visit_array_access(self, node) -> str:
        return f"Array({self.visit(node.array)},{self.visit(node.index)})"

    def visit_member_access(self, node) -> str:
        return f"Member({self.visit(node.object)},{node.member})"

    def visit_condition(self, node) -> str:
        return "Condition()"

    def visit_for_expression(self, node) -> str:
        return f"For({node.quantifier},{node.variable},{self.visit(node.iterable)},{self.visit(node.body)})"

    def visit_for_of_expression(self, node) -> str:
        cond = self.visit(node.condition) if node.condition else ""
        return f"ForOf({node.quantifier},{self.visit(node.string_set)},{cond})"

    def visit_at_expression(self, node) -> str:
        return f"At({node.string_id},{self.visit(node.offset)})"

    def visit_in_expression(self, node) -> str:
        return f"In({node.string_id},{self.visit(node.range)})"

    def visit_of_expression(self, node) -> str:
        quant = (
            self.visit(node.quantifier)
            if hasattr(node.quantifier, "accept")
            else str(node.quantifier)
        )
        string_set = (
            self.visit(node.string_set)
            if hasattr(node.string_set, "accept")
            else str(node.string_set)
        )
        return f"Of({quant},{string_set})"

    def visit_meta(self, node) -> str:
        return f"Meta({node.key},{node.value})"

    def visit_module_reference(self, node) -> str:
        return f"ModRef({node.module})"

    def visit_dictionary_access(self, node) -> str:
        return f"Dict({self.visit(node.object)},{node.key})"

    def visit_comment(self, node) -> str:
        return f"Comment({node.text},{node.is_multiline})"

    def visit_comment_group(self, node) -> str:
        comments = "|".join(self.visit(c) for c in node.comments)
        return f"CommentGroup({comments})"

    def visit_defined_expression(self, node) -> str:
        return f"Defined({self.visit(node.expression)})"

    def visit_string_operator_expression(self, node) -> str:
        return f"StrOp({self.visit(node.left)},{node.operator},{self.visit(node.right)})"

    # Add missing abstract methods
    def visit_extern_import(self, node) -> str:
        return f"ExternImport({node.module if hasattr(node, 'module') else ''})"

    def visit_extern_namespace(self, node) -> str:
        return f"ExternNamespace({node.name if hasattr(node, 'name') else ''})"

    def visit_extern_rule(self, node) -> str:
        return f"ExternRule({node.name if hasattr(node, 'name') else ''})"

    def visit_extern_rule_reference(self, node) -> str:
        return f"ExternRuleRef({node.name if hasattr(node, 'name') else ''})"

    def visit_in_rule_pragma(self, node) -> str:
        return f"InRulePragma({node.pragma if hasattr(node, 'pragma') else ''})"

    def visit_pragma(self, node) -> str:
        return f"Pragma({node.directive if hasattr(node, 'directive') else ''})"

    def visit_pragma_block(self, node) -> str:
        pragmas = (
            ",".join([self.visit(p) for p in node.pragmas]) if hasattr(node, "pragmas") else ""
        )
        return f"PragmaBlock({pragmas})"


class AstDiff:
    """Compares two ASTs and produces incremental diffs."""

    def __init__(self) -> None:
        self.hasher = AstHasher()

    def compare(self, old_ast: YaraFile, new_ast: YaraFile) -> DiffResult:
        """Compare two ASTs and return differences."""
        old_hash = self.hasher.hash_ast(old_ast)
        new_hash = self.hasher.hash_ast(new_ast)

        result = DiffResult(old_ast_hash=old_hash, new_ast_hash=new_hash)

        if old_hash == new_hash:
            # ASTs are identical
            return result

        # Compare file-level elements
        self._compare_imports(old_ast.imports, new_ast.imports, result)
        self._compare_includes(old_ast.includes, new_ast.includes, result)
        self._compare_rules(old_ast.rules, new_ast.rules, result)

        # Add statistics
        result.statistics = {
            "total_changes": len(result.differences),
            "old_rules_count": len(old_ast.rules),
            "new_rules_count": len(new_ast.rules),
            "old_imports_count": len(old_ast.imports),
            "new_imports_count": len(new_ast.imports),
        }

        return result

    def _compare_imports(
        self,
        old_imports: list,
        new_imports: list,
        result: DiffResult,
    ) -> None:
        """Compare import lists."""
        old_modules = {imp.module: imp for imp in old_imports}
        new_modules = {imp.module: imp for imp in new_imports}

        # Find added imports
        for module in new_modules:
            if module not in old_modules:
                result.differences.append(
                    DiffNode(
                        path=f"/imports/{module}",
                        diff_type=DiffType.ADDED,
                        new_value=module,
                        node_type="Import",
                    ),
                )

        # Find removed imports
        for module in old_modules:
            if module not in new_modules:
                result.differences.append(
                    DiffNode(
                        path=f"/imports/{module}",
                        diff_type=DiffType.REMOVED,
                        old_value=module,
                        node_type="Import",
                    ),
                )

        # Find modified imports (alias changes)
        for module in old_modules:
            if module in new_modules:
                old_alias = getattr(old_modules[module], "alias", None)
                new_alias = getattr(new_modules[module], "alias", None)
                if old_alias != new_alias:
                    result.differences.append(
                        DiffNode(
                            path=f"/imports/{module}/alias",
                            diff_type=DiffType.MODIFIED,
                            old_value=old_alias,
                            new_value=new_alias,
                            node_type="Import",
                        ),
                    )

    def _compare_includes(
        self,
        old_includes: list,
        new_includes: list,
        result: DiffResult,
    ) -> None:
        """Compare include lists."""
        old_paths = {inc.path for inc in old_includes}
        new_paths = {inc.path for inc in new_includes}

        # Find added includes
        for path in new_paths - old_paths:
            result.differences.append(
                DiffNode(
                    path=f"/includes/{path}",
                    diff_type=DiffType.ADDED,
                    new_value=path,
                    node_type="Include",
                ),
            )

        # Find removed includes
        for path in old_paths - new_paths:
            result.differences.append(
                DiffNode(
                    path=f"/includes/{path}",
                    diff_type=DiffType.REMOVED,
                    old_value=path,
                    node_type="Include",
                ),
            )

    def _compare_rules(
        self,
        old_rules: list,
        new_rules: list,
        result: DiffResult,
    ) -> None:
        """Compare rule lists."""
        old_rule_map = {rule.name: rule for rule in old_rules}
        new_rule_map = {rule.name: rule for rule in new_rules}

        # Find added rules
        for name in new_rule_map:
            if name not in old_rule_map:
                result.differences.append(
                    DiffNode(
                        path=f"/rules/{name}",
                        diff_type=DiffType.ADDED,
                        new_value=name,
                        node_type="Rule",
                        details={
                            "rule_summary": self._get_rule_summary(new_rule_map[name]),
                        },
                    ),
                )

        # Find removed rules
        for name in old_rule_map:
            if name not in new_rule_map:
                result.differences.append(
                    DiffNode(
                        path=f"/rules/{name}",
                        diff_type=DiffType.REMOVED,
                        old_value=name,
                        node_type="Rule",
                        details={
                            "rule_summary": self._get_rule_summary(old_rule_map[name]),
                        },
                    ),
                )

        # Find modified rules
        for name in old_rule_map:
            if name in new_rule_map:
                self._compare_rule_content(
                    old_rule_map[name],
                    new_rule_map[name],
                    f"/rules/{name}",
                    result,
                )

    def _compare_rule_content(
        self,
        old_rule,
        new_rule,
        base_path: str,
        result: DiffResult,
    ) -> None:
        """Compare content of two rules."""
        # Compare modifiers
        if set(old_rule.modifiers) != set(new_rule.modifiers):
            result.differences.append(
                DiffNode(
                    path=f"{base_path}/modifiers",
                    diff_type=DiffType.MODIFIED,
                    old_value=list(old_rule.modifiers),
                    new_value=list(new_rule.modifiers),
                    node_type="RuleModifiers",
                ),
            )

        # Compare tags
        old_tag_names = {tag.name for tag in old_rule.tags}
        new_tag_names = {tag.name for tag in new_rule.tags}
        if old_tag_names != new_tag_names:
            result.differences.append(
                DiffNode(
                    path=f"{base_path}/tags",
                    diff_type=DiffType.MODIFIED,
                    old_value=list(old_tag_names),
                    new_value=list(new_tag_names),
                    node_type="RuleTags",
                ),
            )

        # Compare meta
        if old_rule.meta != new_rule.meta:
            result.differences.append(
                DiffNode(
                    path=f"{base_path}/meta",
                    diff_type=DiffType.MODIFIED,
                    old_value=dict(old_rule.meta),
                    new_value=dict(new_rule.meta),
                    node_type="RuleMeta",
                ),
            )

        # Compare strings
        self._compare_rule_strings(
            old_rule.strings,
            new_rule.strings,
            f"{base_path}/strings",
            result,
        )

        # Compare condition (simplified)
        old_condition_hash = self.hasher.visit(old_rule.condition) if old_rule.condition else ""
        new_condition_hash = self.hasher.visit(new_rule.condition) if new_rule.condition else ""
        if old_condition_hash != new_condition_hash:
            result.differences.append(
                DiffNode(
                    path=f"{base_path}/condition",
                    diff_type=DiffType.MODIFIED,
                    old_value=old_condition_hash,
                    new_value=new_condition_hash,
                    node_type="RuleCondition",
                ),
            )

    def _compare_rule_strings(
        self,
        old_strings: list,
        new_strings: list,
        base_path: str,
        result: DiffResult,
    ) -> None:
        """Compare string definitions in rules."""
        old_string_map = {s.identifier: s for s in old_strings}
        new_string_map = {s.identifier: s for s in new_strings}

        # Find added strings
        for identifier in new_string_map:
            if identifier not in old_string_map:
                result.differences.append(
                    DiffNode(
                        path=f"{base_path}/{identifier}",
                        diff_type=DiffType.ADDED,
                        new_value=identifier,
                        node_type="StringDefinition",
                    ),
                )

        # Find removed strings
        for identifier in old_string_map:
            if identifier not in new_string_map:
                result.differences.append(
                    DiffNode(
                        path=f"{base_path}/{identifier}",
                        diff_type=DiffType.REMOVED,
                        old_value=identifier,
                        node_type="StringDefinition",
                    ),
                )

        # Find modified strings
        for identifier in old_string_map:
            if identifier in new_string_map:
                old_hash = self.hasher.visit(old_string_map[identifier])
                new_hash = self.hasher.visit(new_string_map[identifier])
                if old_hash != new_hash:
                    result.differences.append(
                        DiffNode(
                            path=f"{base_path}/{identifier}",
                            diff_type=DiffType.MODIFIED,
                            old_value=old_hash,
                            new_value=new_hash,
                            node_type="StringDefinition",
                        ),
                    )

    def _get_rule_summary(self, rule) -> dict[str, Any]:
        """Get a summary of a rule for diff details."""
        return {
            "name": rule.name,
            "modifiers": rule.modifiers,
            "tags_count": len(rule.tags),
            "meta_count": len(rule.meta),
            "strings_count": len(rule.strings),
            "has_condition": rule.condition is not None,
        }

    def create_patch(
        self,
        diff_result: DiffResult,
        output_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Create a patch file from diff result."""
        patch = {
            "patch_format": "yaraast-diff-v1",
            "old_hash": diff_result.old_ast_hash,
            "new_hash": diff_result.new_ast_hash,
            "timestamp": int(time.time()),
            "changes": diff_result.to_dict(),
        }

        if output_path:
            import json

            with Path(output_path).open("w") as f:
                json.dump(patch, f, indent=2)

        return patch
