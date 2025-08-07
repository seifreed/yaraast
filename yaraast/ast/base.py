"""Base AST node classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from yaraast.ast.comments import Comment
    from yaraast.ast.extern import ExternRule
    from yaraast.ast.imports import ExternImport, ExternNamespace, Import, Include
    from yaraast.ast.pragmas import Pragma, PragmaType
    from yaraast.ast.rules import Rule


@dataclass
class Location:
    """Source location information for AST nodes."""

    line: int
    column: int
    file: str | None = None


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
    def accept(self, visitor: Any) -> Any:
        """Accept a visitor for the visitor pattern."""

    def children(self) -> list[ASTNode]:
        """Return child nodes."""
        from dataclasses import fields

        children = []
        for f in fields(self):
            if f.name == "location":
                continue
            value = getattr(self, f.name)
            if isinstance(value, ASTNode):
                children.append(value)
            elif isinstance(value, list):
                children.extend(v for v in value if isinstance(v, ASTNode))
        return children


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

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_yara_file(self)

    def add_extern_rule(self, extern_rule: ExternRule) -> None:
        """Add an extern rule to the file."""
        self.extern_rules.append(extern_rule)

    def add_pragma(self, pragma: Pragma) -> None:
        """Add a file-level pragma."""
        from yaraast.ast.pragmas import PragmaScope

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
        return None

    def get_all_rules(self) -> list[Rule]:
        """Get all rules (regular + extern converted to regular for compatibility)."""
        return self.rules.copy()  # For now, just return regular rules
