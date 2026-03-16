"""Module-related types and environment."""

from __future__ import annotations

from dataclasses import dataclass

from ._registry_base import YaraType
from .module_contracts import ModuleDefinition


@dataclass
class ModuleType(YaraType):
    """Module type with attributes."""

    module_name: str
    attributes: dict[str, YaraType]

    def __str__(self) -> str:
        return f"module({self.module_name})"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, ModuleType) and other.module_name == self.module_name

    def get_attribute_type(self, attr: str) -> YaraType | None:
        """Get type of module attribute."""
        return self.attributes.get(attr)


@dataclass
class FunctionType(YaraType):
    """Function type."""

    name: str
    param_types: list[YaraType]
    return_type: YaraType

    def __str__(self) -> str:
        params = ", ".join(str(p) for p in self.param_types)
        return f"{self.name}({params}) -> {self.return_type}"

    def is_compatible_with(self, other: YaraType) -> bool:
        return False


class TypeSystem:
    """Type system with module support."""

    def __init__(self) -> None:
        self.modules: dict[str, ModuleDefinition] = {}
        self._init_modules()

    def _init_modules(self) -> None:
        """Initialize modules using ModuleLoader."""
        try:
            from yaraast.types.module_loader import ModuleLoader

            loader = ModuleLoader()
            self.modules = loader.modules
        except ImportError:
            self._init_builtin_modules()

    def _init_builtin_modules(self) -> None:
        """Initialize builtin modules (fallback)."""
        from .module_definitions import load_builtin_modules

        builtins = load_builtin_modules()
        self.modules = {name: builtins[name] for name in ("pe", "math") if name in builtins}

    def get_module(self, name: str) -> ModuleDefinition | None:
        """Get module definition by name."""
        return self.modules.get(name)
