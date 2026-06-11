"""Module-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import _require_nonempty_string, _VisitorType
from yaraast.ast.expressions import Expression, _validate_expression


@dataclass
class ModuleReference(Expression):
    """Reference to a module (e.g., pe, math, dotnet)."""

    module: str

    def validate_structure(self) -> None:
        """Validate module name before direct analysis."""
        _require_nonempty_string(self.module, "ModuleReference module")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_module_reference(self)


@dataclass
class DictionaryAccess(Expression):
    """Dictionary-style access (e.g., pe.version_info["CompanyName"])."""

    object: Expression
    key: str | Expression

    def validate_structure(self) -> None:
        """Validate dictionary object and key before direct analysis."""
        _validate_expression(self.object, "DictionaryAccess.object")
        if isinstance(self.key, str):
            _require_nonempty_string(self.key, "DictionaryAccess key")
        else:
            _validate_expression(self.key, "DictionaryAccess.key")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_dictionary_access(self)
