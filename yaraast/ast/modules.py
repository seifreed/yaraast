"""Module-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.expressions import Expression


@dataclass
class ModuleReference(Expression):
    """Reference to a module (e.g., pe, math, dotnet)."""

    module: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_module_reference(self)


@dataclass
class DictionaryAccess(Expression):
    """Dictionary-style access (e.g., pe.version_info["CompanyName"])."""

    object: Expression
    key: str | Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_dictionary_access(self)
