"""Module loader for loading YARA module definitions from JSON."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from yaraast.types._registry_base import YaraType
from yaraast.types.module_contracts import FunctionDefinition, ModuleDefinition
from yaraast.types.module_definitions import load_builtin_modules


class ModuleLoader:
    """Load YARA module definitions from JSON files."""

    def __init__(self) -> None:
        self.modules: dict[str, ModuleDefinition] = {}
        self._load_builtin_modules()
        self._load_json_modules()

    def _load_builtin_modules(self) -> None:
        """Load hardcoded builtin modules."""
        self.modules.update(load_builtin_modules())

    def _load_json_modules(self) -> None:
        """Load modules from JSON files based on environment variables."""
        # Check environment variables
        module_paths = []

        # YARAAST_MODULE_SPEC_PATH - additional paths
        if os.environ.get("YARAAST_MODULE_SPEC_PATH"):
            paths = os.environ["YARAAST_MODULE_SPEC_PATH"].split(os.pathsep)
            module_paths.extend(paths)

        # YARAAST_MODULE_SPEC_PATH_EXCLUSIVE - exclusive paths (ignore builtins)
        exclusive_mode = False
        if os.environ.get("YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"):
            exclusive_mode = True
            self.modules.clear()  # Clear builtin modules
            paths = os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"].split(os.pathsep)
            module_paths.extend(paths)

        # Default location (only if not in exclusive mode)
        if not exclusive_mode:
            default_path = Path(__file__).parent / "modules"
            if default_path.exists() and str(default_path) not in module_paths:
                module_paths.append(str(default_path))

        # Load modules from all paths
        for path_str in module_paths:
            path = Path(path_str)
            if path.is_file() and path.suffix == ".json":
                self._load_module_file(path)
            elif path.is_dir():
                for json_file in path.glob("*.json"):
                    self._load_module_file(json_file)

    def _load_module_file(self, path: Path) -> None:
        """Load a single module definition from JSON file."""
        try:
            with Path(path).open(encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                # Single module in file
                module = self._parse_module(path.stem, data)
                if module:
                    self.modules[module.name] = module
            elif isinstance(data, list):
                # Multiple modules in file
                for module_data in data:
                    if isinstance(module_data, dict) and "name" in module_data:
                        module = self._parse_module(module_data["name"], module_data)
                        if module:
                            self.modules[module.name] = module
        except (ValueError, TypeError, AttributeError):
            pass

    def _parse_module(self, name: str, data: dict[str, Any]) -> ModuleDefinition | None:
        """Parse module definition from JSON data."""
        try:
            module = ModuleDefinition(name=data.get("name", name))

            # Parse attributes
            if "attributes" in data:
                for attr_name, attr_type in data["attributes"].items():
                    module.attributes[attr_name] = self._parse_type(attr_type)

            # Parse functions
            if "functions" in data:
                for func_name, func_data in data["functions"].items():
                    if isinstance(func_data, dict):
                        func_def = FunctionDefinition(
                            name=func_name,
                            return_type=self._parse_type(
                                func_data.get("return", "any"),
                            ),
                            parameters=self._parse_parameters(
                                func_data.get("parameters", []),
                            ),
                        )
                        module.functions[func_name] = func_def

            # Parse constants
            if "constants" in data:
                for const_name, const_type in data["constants"].items():
                    module.constants[const_name] = self._parse_type(const_type)

            return module

        except (ValueError, TypeError, AttributeError):
            return None

    def _parse_type(self, type_str: str | dict) -> YaraType:
        """Parse type from string or dict representation."""
        from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
        from yaraast.types._registry_primitives import (
            AnyType,
            BooleanType,
            FloatType,
            IntegerType,
            StringType,
        )

        if isinstance(type_str, str):
            # Simple types
            type_map = {
                "int": IntegerType(),
                "integer": IntegerType(),
                "string": StringType(),
                "str": StringType(),
                "bool": BooleanType(),
                "boolean": BooleanType(),
                "float": FloatType(),
                "double": FloatType(),
                "any": AnyType(),
            }

            # Check for array syntax: type[]
            if type_str.endswith("[]"):
                base_type = type_str[:-2]
                return ArrayType(self._parse_type(base_type))

            return type_map.get(type_str.lower(), AnyType())

        if isinstance(type_str, dict):
            # Complex types
            if type_str.get("type") == "array":
                return ArrayType(self._parse_type(type_str.get("element", "any")))
            if type_str.get("type") == "dict":
                return DictionaryType(
                    self._parse_type(type_str.get("key", "string")),
                    self._parse_type(type_str.get("value", "any")),
                )
            if type_str.get("type") == "struct":
                fields = {}
                for field_name, field_type in type_str.get("fields", {}).items():
                    fields[field_name] = self._parse_type(field_type)
                return StructType(fields)

        return AnyType()

    def _parse_parameters(self, params: list | dict) -> list[tuple[str, YaraType]]:
        """Parse function parameters."""
        result = []

        if isinstance(params, list):
            # List of parameter names (assume any type)
            for param in params:
                if isinstance(param, str):
                    result.append((param, self._parse_type("any")))
                elif isinstance(param, dict):
                    name = param.get("name", f"param_{len(result)}")
                    type_ = self._parse_type(param.get("type", "any"))
                    result.append((name, type_))

        elif isinstance(params, dict):
            # Dict of name: type
            for name, type_str in params.items():
                result.append((name, self._parse_type(type_str)))

        return result

    def get_module(self, name: str) -> ModuleDefinition | None:
        """Get module definition by name."""
        return self.modules.get(name)

    def list_modules(self) -> list[str]:
        """List all available module names."""
        return sorted(self.modules.keys())


# Example JSON module format:
EXAMPLE_MODULE_JSON = """
{
    "name": "custom",
    "description": "Custom module for demonstration",
    "attributes": {
        "version": "string",
        "data": "string[]"
    },
    "functions": {
        "calculate": {
            "return": "int",
            "parameters": [
                {"name": "x", "type": "int"},
                {"name": "y", "type": "int"}
            ]
        },
        "check": {
            "return": "bool",
            "parameters": {
                "value": "string"
            }
        }
    },
    "constants": {
        "MAX_SIZE": "int",
        "MODULE_NAME": "string"
    }
}
"""
