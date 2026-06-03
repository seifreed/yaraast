"""Base AST node classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from yaraast.ast.comments import Comment
    from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
    from yaraast.ast.pragmas import Pragma, PragmaType
    from yaraast.ast.rules import Import, Include, Rule

    _VisitorType = Any
else:
    _VisitorType = Any


@dataclass
class Location:
    """Source location information for AST nodes."""

    line: int
    column: int
    file: str | None = None
    end_line: int | None = None
    end_column: int | None = None


@dataclass
class ASTNode(ABC):
    """Base class for all AST nodes."""

    location: Location | None = field(default=None, init=False, compare=False)
    leading_comments: list[Comment] = field(
        default_factory=list,
        init=False,
        compare=False,
    )
    trailing_comment: Comment | None = field(default=None, init=False, compare=False)

    @abstractmethod
    def accept(self, visitor: _VisitorType) -> Any:
        """Accept a visitor for the visitor pattern."""

    _METADATA_FIELDS = frozenset({"location", "leading_comments", "trailing_comment"})

    def children(self) -> list[ASTNode]:
        """Return semantic child nodes (excludes metadata like location and comments)."""
        from dataclasses import fields

        def collect_from_items(values: Iterable[Any]) -> list[ASTNode]:
            nested_children: list[ASTNode] = []
            for item in values:
                nested_children.extend(collect_children(item))
            return nested_children

        def collect_children(value: Any) -> list[ASTNode]:
            if isinstance(value, ASTNode):
                return [value]
            if isinstance(value, Mapping):
                return collect_from_items(value.values())
            if isinstance(value, list | tuple | set | frozenset):
                return collect_from_items(value)
            return []

        children = []
        for f in fields(self):
            if f.name in self._METADATA_FIELDS:
                continue
            value = getattr(self, f.name)
            children.extend(collect_children(value))
        return children


def require_string(value: Any, field_name: str) -> str:
    """Require a ``str`` value, raising ``TypeError`` otherwise.

    A leaf guard reused across layers (AST construction, serialization, CLI)
    so the identical check is defined once.
    """
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


def require_optional_string(value: Any, field_name: str) -> str | None:
    """Require ``None`` or a ``str`` value, raising ``TypeError`` otherwise."""
    if value is None:
        return None
    return require_string(value, field_name)


def _require_ast_node(value: Any, field_name: str) -> ASTNode:
    if not isinstance(value, ASTNode):
        msg = f"{field_name} must be an AST node"
        raise TypeError(msg)
    return value


def _require_ast_node_sequence(values: Any, field_name: str) -> list[ASTNode]:
    if not isinstance(values, list | tuple):
        msg = f"{field_name.replace('.', ' ')} must be a list or tuple"
        raise TypeError(msg)
    for value in values:
        if not isinstance(value, ASTNode):
            msg = f"{field_name} must contain AST nodes"
            raise TypeError(msg)
    return list(values)


def _require_ast_node_sequence_type(
    values: Any,
    field_name: str,
    expected_type: type[ASTNode] | tuple[type[ASTNode], ...],
    expected_name: str,
) -> list[ASTNode]:
    if not isinstance(values, list | tuple):
        msg = f"{field_name.replace('.', ' ')} must be a list or tuple"
        raise TypeError(msg)
    for value in values:
        if not isinstance(value, expected_type):
            msg = f"{field_name.replace('.', ' ')} must contain {expected_name} nodes"
            raise TypeError(msg)
    return list(values)


@dataclass
class YaraFile(ASTNode):
    """Root node representing a complete YARA file with enhanced syntax support."""

    imports: list[Import] = field(default_factory=list)
    includes: list[Include] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    extern_rules: list[ExternRule] = field(default_factory=list)
    extern_imports: list[ExternImport] = field(default_factory=list)
    pragmas: list[Pragma] = field(default_factory=list)
    namespaces: list[ExternNamespace] = field(default_factory=list)

    def validate_structure(self, *, deep: bool = True) -> None:
        """Validate child containers before traversal."""
        from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
        from yaraast.ast.pragmas import Pragma
        from yaraast.ast.rules import Import, Include, Rule

        _require_ast_node_sequence_type(self.imports, "YaraFile.imports", Import, "Import")
        _require_ast_node_sequence_type(self.includes, "YaraFile.includes", Include, "Include")
        _require_ast_node_sequence_type(self.rules, "YaraFile.rules", Rule, "Rule")
        _require_ast_node_sequence_type(
            self.extern_rules,
            "YaraFile.extern_rules",
            ExternRule,
            "ExternRule",
        )
        _require_ast_node_sequence_type(
            self.extern_imports,
            "YaraFile.extern_imports",
            ExternImport,
            "ExternImport",
        )
        _require_ast_node_sequence_type(self.pragmas, "YaraFile.pragmas", Pragma, "Pragma")
        _require_ast_node_sequence_type(
            self.namespaces,
            "YaraFile.namespaces",
            ExternNamespace,
            "ExternNamespace",
        )
        if deep:
            for item in (
                *self.imports,
                *self.includes,
                *self.rules,
                *self.extern_rules,
                *self.extern_imports,
                *self.pragmas,
                *self.namespaces,
            ):
                validate_structure = getattr(item, "validate_structure", None)
                if callable(validate_structure):
                    validate_structure()

    def accept(self, visitor: _VisitorType) -> Any:
        self.validate_structure(deep=False)
        return visitor.visit_yara_file(self)

    def add_extern_rule(self, extern_rule: ExternRule) -> None:
        """Add an extern rule to the file."""
        from yaraast.ast.extern import ExternRule

        if not isinstance(extern_rule, ExternRule):
            msg = "Extern rule input must be an ExternRule"
            raise TypeError(msg)
        self.extern_rules.append(extern_rule)

    def add_pragma(self, pragma: Pragma) -> None:
        """Add a file-level pragma."""
        from yaraast.ast.pragmas import Pragma, PragmaScope

        if not isinstance(pragma, Pragma):
            msg = "Pragma input must be a Pragma"
            raise TypeError(msg)

        pragma.scope = PragmaScope.FILE
        self.pragmas.append(pragma)

    def get_pragma_by_type(self, pragma_type: PragmaType) -> list[Pragma]:
        """Get all pragmas of a specific type."""
        return [p for p in self.pragmas if p.pragma_type == pragma_type]

    def has_include_once(self) -> bool:
        """Check if file has include_once pragma."""
        from yaraast.ast.pragmas import PragmaType

        return any(p.pragma_type == PragmaType.INCLUDE_ONCE for p in self.pragmas)

    def get_extern_rule_by_name(
        self,
        name: str,
        namespace: str | None = None,
    ) -> ExternRule | None:
        """Get extern rule by name and optional namespace."""
        for rule in self.extern_rules:
            if rule.name == name and rule.namespace == namespace:
                return rule
        for extern_namespace in self.namespaces:
            if namespace is not None and extern_namespace.name != namespace:
                continue
            for rule in extern_namespace.extern_rules:
                rule_namespace = rule.namespace or extern_namespace.name
                if rule.name == name and rule_namespace == namespace:
                    return rule
        return None

    def get_all_rules(self) -> list[Rule]:
        """Get a copy of all regular rules in this file."""
        return self.rules.copy()


def require_yara_file(value: object, name: str) -> YaraFile:
    """Require a YaraFile instance for public AST APIs."""
    if not isinstance(value, YaraFile):
        msg = f"{name} must be a YaraFile"
        raise TypeError(msg)
    return value
