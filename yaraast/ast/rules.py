"""Rule-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import ASTNode
from yaraast.ast.modifiers import MetaEntry, RuleModifier

if TYPE_CHECKING:
    from yaraast.ast.conditions import Condition
    from yaraast.ast.pragmas import InRulePragma
    from yaraast.ast.strings import StringDefinition


@dataclass
class Import(ASTNode):
    """Import statement node."""

    module: str
    alias: str | None = None  # Support for 'import "module" as alias'

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_import(self)


@dataclass
class Include(ASTNode):
    """Include statement node."""

    path: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_include(self)


@dataclass
class Tag(ASTNode):
    """Rule tag node."""

    name: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_tag(self)


@dataclass
class Rule(ASTNode):
    """YARA rule node with enhanced modifier and meta support."""

    name: str
    modifiers: list[str | RuleModifier] = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    meta: dict[str, Any] | list[MetaEntry] = field(default_factory=list)
    strings: list[StringDefinition] = field(default_factory=list)
    condition: Condition | None = None
    pragmas: list[InRulePragma] = field(default_factory=list)

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_rule(self)

    @property
    def is_private(self) -> bool:
        """Check if rule is private."""
        return any(str(m) == "private" for m in self.modifiers)

    @property
    def is_global(self) -> bool:
        """Check if rule is global."""
        return any(str(m) == "global" for m in self.modifiers)

    def get_meta_entries(self) -> list[MetaEntry]:
        """Get meta entries as enhanced MetaEntry objects."""
        if isinstance(self.meta, list):
            return self.meta
        # Convert dict to MetaEntry list
        return [MetaEntry.from_key_value(k, v) for k, v in self.meta.items()]

    def get_private_meta(self) -> list[MetaEntry]:
        """Get only private meta entries."""
        entries = self.get_meta_entries()
        return [entry for entry in entries if entry.is_private]

    def get_public_meta(self) -> list[MetaEntry]:
        """Get only public meta entries."""
        entries = self.get_meta_entries()
        return [entry for entry in entries if entry.is_public]

    def add_pragma(self, pragma: InRulePragma) -> None:
        """Add a pragma to this rule."""
        self.pragmas.append(pragma)

    def get_pragmas_by_position(self, position: str) -> list[InRulePragma]:
        """Get pragmas by their position in the rule."""
        return [p for p in self.pragmas if p.position == position]
