"""Rule-related AST nodes."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import (
    ASTNode,
    _require_ast_node,
    _require_ast_node_sequence_type,
    _require_nonempty_string,
    _require_optional_nonempty_string,
    _VisitorType,
    require_string,
)
from yaraast.ast.modifiers import MetaEntry, RuleModifier, require_rule_modifier_identifier
from yaraast.errors import ValidationError
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH

if TYPE_CHECKING:
    from yaraast.ast.expressions import Expression
    from yaraast.ast.pragmas import InRulePragma
    from yaraast.ast.strings import StringDefinition

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)


def _validate_yara_identifier(name: object, kind: str) -> str:
    if not isinstance(name, str):
        msg = f"{kind.capitalize()} identifier must be a string for libyara output"
        raise TypeError(msg)
    if (
        len(name) <= YARA_IDENTIFIER_MAX_LENGTH
        and _YARA_IDENTIFIER_RE.fullmatch(name) is not None
        and name not in _YARA_KEYWORDS
    ):
        return name
    msg = f"Invalid {kind} identifier '{name}' for libyara output"
    raise ValueError(msg)


@dataclass
class Import(ASTNode):
    """Import statement node."""

    module: str
    alias: str | None = None  # Support for 'import "module" as alias'

    def validate_structure(self) -> None:
        """Validate import scalar fields before direct analysis."""
        _require_nonempty_string(self.module, "Import module")
        if self.alias is not None:
            _require_optional_nonempty_string(self.alias, "Import alias")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_import(self)


@dataclass
class Include(ASTNode):
    """Include statement node."""

    path: str

    def validate_structure(self) -> None:
        """Validate include scalar fields before direct analysis."""
        _require_nonempty_string(self.path, "Include path")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_include(self)


@dataclass
class Tag(ASTNode):
    """Rule tag node."""

    name: str

    def validate_structure(self) -> None:
        """Validate tag scalar fields before direct analysis."""
        _require_nonempty_string(self.name, "Tag name")
        _validate_yara_identifier(self.name, "tag")

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

    def validate_structure(self) -> None:
        """Validate child containers before traversal."""
        _require_nonempty_string(self.name, "Rule name")
        _validate_yara_identifier(self.name, "rule")
        from yaraast.ast.strings import StringDefinition

        _require_ast_node_sequence_type(
            self.tags,
            "Rule.tags",
            Tag,
            "Tag",
        )
        _require_ast_node_sequence_type(
            self.strings,
            "Rule.strings",
            StringDefinition,
            "StringDefinition",
        )
        self._validated_pragmas()
        self._validated_modifiers()
        self._validated_meta_entries()
        if self.condition is not None:
            _require_ast_node(self.condition, "Rule.condition")
        for tag in self.tags:
            tag.validate_structure()
        for pragma in self._validated_pragmas():
            pragma.validate_structure()
        for string in self.strings:
            validate_structure = getattr(string, "validate_structure", None)
            if callable(validate_structure):
                validate_structure()
        if self.condition is not None:
            validate_structure = getattr(self.condition, "validate_structure", None)
            if callable(validate_structure):
                validate_structure()

    def _validated_modifiers(self) -> list[RuleModifier | str]:
        if not isinstance(self.modifiers, list):
            msg = "Rule modifiers must be a list"
            raise TypeError(msg)
        modifiers: list[RuleModifier | str] = []
        for modifier in self.modifiers:
            if isinstance(modifier, RuleModifier):
                modifier.validate_structure()
                modifiers.append(modifier)
            elif isinstance(modifier, str):
                modifiers.append(
                    require_rule_modifier_identifier(
                        modifier,
                        "Rule modifier",
                        "rule modifier",
                    )
                )
            else:
                msg = "Rule modifiers item must be RuleModifier or string"
                raise TypeError(msg)
        return modifiers

    def _validated_meta_entries(self) -> list[MetaEntry]:
        from yaraast.ast.meta import Meta

        if self.meta is None:
            return []
        if isinstance(self.meta, dict):
            return [MetaEntry.from_key_value(key, value) for key, value in self.meta.items()]
        if not isinstance(self.meta, list | tuple):
            msg = "Rule meta must be a list or tuple"
            raise TypeError(msg)

        entries: list[MetaEntry] = []
        for meta in self.meta:
            if isinstance(meta, MetaEntry):
                meta.validate_structure()
                entries.append(meta)
            elif isinstance(meta, Meta):
                meta.validate_structure()
                entries.append(MetaEntry.from_key_value(meta.key, meta.value))
            else:
                msg = "Rule meta must contain Meta or MetaEntry nodes"
                raise TypeError(msg)
        return entries

    def _validated_pragmas(self) -> list[InRulePragma]:
        from yaraast.ast.pragmas import InRulePragma

        _require_ast_node_sequence_type(
            self.pragmas,
            "Rule.pragmas",
            InRulePragma,
            "InRulePragma",
        )
        return list(self.pragmas)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_rule(self)

    @property
    def is_private(self) -> bool:
        """Check if rule is private."""
        return any(str(modifier) == "private" for modifier in self._validated_modifiers())

    @property
    def is_global(self) -> bool:
        """Check if rule is global."""
        return any(str(modifier) == "global" for modifier in self._validated_modifiers())

    def get_meta_entries(self) -> list[MetaEntry]:
        """Get meta entries as enhanced MetaEntry objects."""
        return self._validated_meta_entries()

    def get_meta_value(self, key: str, default: Any = None) -> Any:
        """Get the value of a meta entry by key."""
        key = require_string(key, "Rule meta key")
        for entry in reversed(self._validated_meta_entries()):
            if entry.key == key:
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
        pragma.validate_structure()
        self.pragmas.append(pragma)

    def get_pragmas_by_position(self, position: str) -> list[InRulePragma]:
        """Get pragmas by their position in the rule."""
        position = require_string(position, "Rule pragma position")
        return [p for p in self._validated_pragmas() if p.position == position]
