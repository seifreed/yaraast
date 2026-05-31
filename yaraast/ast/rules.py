"""Rule-related AST nodes."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from yaraast.ast.base import ASTNode, _VisitorType
from yaraast.ast.modifiers import MetaEntry, RuleModifier
from yaraast.errors import ValidationError

if TYPE_CHECKING:
    from yaraast.ast.expressions import Expression
    from yaraast.ast.pragmas import InRulePragma
    from yaraast.ast.strings import StringDefinition


@dataclass
class Import(ASTNode):
    """Import statement node."""

    module: str
    alias: str | None = None  # Support for 'import "module" as alias'

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_import(self)


@dataclass
class Include(ASTNode):
    """Include statement node."""

    path: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_include(self)


@dataclass
class Tag(ASTNode):
    """Rule tag node."""

    name: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_tag(self)


@dataclass
class Rule(ASTNode):
    """YARA rule node with enhanced modifier and meta support."""

    name: str
    modifiers: Any = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    meta: Any = field(default_factory=list)
    strings: list[StringDefinition] = field(default_factory=list)
    condition: Expression | None = None
    pragmas: list[InRulePragma] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Normalize modifiers to RuleModifier and meta to list[MetaEntry]."""
        self.modifiers = self._normalize_modifiers(self.modifiers)
        self.meta = self._normalize_meta(self.meta)

    @classmethod
    def from_raw(
        cls,
        name: str,
        modifiers: list[Any] | str | None = None,
        meta: dict[str, Any] | list[MetaEntry] | None = None,
        **kwargs: Any,
    ) -> Rule:
        """Create a Rule with automatic normalization of modifiers and meta.

        Accepts both legacy formats (str modifiers, dict meta) and normalized
        formats (RuleModifier list, MetaEntry list).

        Examples:
            >>> rule = Rule.from_raw("test", modifiers=["private"], meta={"author": "me"})
            >>> rule.is_private
            True
            >>> rule.get_meta_value("author")
            'me'
        """
        normalized_mods = cls._normalize_modifiers(modifiers)
        normalized_meta = cls._normalize_meta(meta)
        return cls(
            name=name,
            modifiers=normalized_mods,
            meta=normalized_meta,
            **kwargs,
        )

    @staticmethod
    def _normalize_modifiers(
        modifiers: Sequence[Any] | str | None,
    ) -> list[Any]:
        """Normalize modifiers to a list of RuleModifier."""
        if modifiers is None:
            return []
        if isinstance(modifiers, str):
            if modifiers == "":
                return []
            try:
                return [RuleModifier.from_string(modifiers)]
            except (ValueError, ValidationError):
                return [modifiers]
        if isinstance(modifiers, list | tuple):
            normalized: list[Any] = []
            for m in modifiers:
                if isinstance(m, str):
                    try:
                        normalized.append(RuleModifier.from_string(m))
                    except (ValueError, ValidationError):
                        normalized.append(m)
                else:
                    normalized.append(m)
            return normalized
        return [modifiers]

    @staticmethod
    def _normalize_meta(meta: Any) -> list[Any]:
        """Normalize meta to a list of MetaEntry."""
        if meta is None:
            return []
        if isinstance(meta, dict):
            return [MetaEntry.from_key_value(k, v) for k, v in meta.items()]
        if isinstance(meta, list | tuple):
            return list(meta)
        return [meta]

    def accept(self, visitor: _VisitorType) -> Any:
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
        return cast(list[MetaEntry], self.meta)

    def get_meta_value(self, key: str, default: Any = None) -> Any:
        """Get the value of a meta entry by key."""
        for entry in reversed(self.meta):
            if hasattr(entry, "key") and entry.key == key:
                return entry.value
        return default

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
        from yaraast.ast.pragmas import InRulePragma

        if not isinstance(pragma, InRulePragma):
            msg = "Rule pragma input must be an InRulePragma"
            raise TypeError(msg)
        self.pragmas.append(pragma)

    def get_pragmas_by_position(self, position: str) -> list[InRulePragma]:
        """Get pragmas by their position in the rule."""
        return [p for p in self.pragmas if p.position == position]
