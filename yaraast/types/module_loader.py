"""Module loader for loading YARA module definitions from JSON."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from yaraast.types.type_system import FunctionDefinition, ModuleDefinition, YaraType


class ModuleLoader:
    """Load YARA module definitions from JSON files."""

    def __init__(self) -> None:
        self.modules: dict[str, ModuleDefinition] = {}
        self._load_builtin_modules()
        self._load_json_modules()

    def _load_builtin_modules(self) -> None:
        """Load hardcoded builtin modules."""
        # PE module
        from yaraast.types.type_system import (
            ArrayType,
            BooleanType,
            DictionaryType,
            DoubleType,
            IntegerType,
            StringType,
            StructType,
        )

        pe = ModuleDefinition(name="pe")
        pe.attributes = {
            "machine": IntegerType(),
            "number_of_sections": IntegerType(),
            "timestamp": IntegerType(),
            "characteristics": IntegerType(),
            "entry_point": IntegerType(),
            "image_base": IntegerType(),
            "sections": ArrayType(
                StructType(
                    {
                        "name": StringType(),
                        "virtual_address": IntegerType(),
                        "virtual_size": IntegerType(),
                        "raw_size": IntegerType(),
                        "characteristics": IntegerType(),
                    },
                ),
            ),
            "version_info": DictionaryType(StringType(), StringType()),
            "number_of_resources": IntegerType(),
            "resource_timestamp": IntegerType(),
            "imports": ArrayType(StringType()),
            "exports": ArrayType(StringType()),
            "is_pe": BooleanType(),
            "is_dll": BooleanType(),
            "is_32bit": BooleanType(),
            "is_64bit": BooleanType(),
        }
        pe.functions = {
            "imphash": FunctionDefinition("imphash", StringType()),
            "section_index": FunctionDefinition(
                "section_index",
                IntegerType(),
                [("name", StringType())],
            ),
            "exports": FunctionDefinition(
                "exports",
                BooleanType(),
                [("name", StringType())],
            ),
            "imports": FunctionDefinition(
                "imports",
                BooleanType(),
                [("dll", StringType()), ("function", StringType())],
            ),
            "locale": FunctionDefinition(
                "locale",
                BooleanType(),
                [("locale", IntegerType())],
            ),
            "language": FunctionDefinition(
                "language",
                BooleanType(),
                [("lang", IntegerType())],
            ),
            # Add functions that can also be called as attributes
            "is_dll": FunctionDefinition("is_dll", BooleanType()),
            "is_64bit": FunctionDefinition("is_64bit", BooleanType()),
            "is_32bit": FunctionDefinition("is_32bit", BooleanType()),
            "rva_to_offset": FunctionDefinition(
                "rva_to_offset",
                IntegerType(),
                [("rva", IntegerType())],
            ),
        }
        self.modules["pe"] = pe

        # Math module
        math = ModuleDefinition(name="math")
        math.functions = {
            "abs": FunctionDefinition("abs", IntegerType(), [("x", IntegerType())]),
            "min": FunctionDefinition(
                "min",
                IntegerType(),
                [("a", IntegerType()), ("b", IntegerType())],
            ),
            "max": FunctionDefinition(
                "max",
                IntegerType(),
                [("a", IntegerType()), ("b", IntegerType())],
            ),
            "to_string": FunctionDefinition(
                "to_string",
                StringType(),
                [("n", IntegerType()), ("base", IntegerType())],
            ),
            "to_number": FunctionDefinition(
                "to_number",
                IntegerType(),
                [("s", StringType())],
            ),
            "log": FunctionDefinition("log", DoubleType(), [("x", DoubleType())]),
            "log2": FunctionDefinition("log2", DoubleType(), [("x", DoubleType())]),
            "log10": FunctionDefinition("log10", DoubleType(), [("x", DoubleType())]),
            "sqrt": FunctionDefinition("sqrt", DoubleType(), [("x", DoubleType())]),
            "entropy": FunctionDefinition(
                "entropy",
                DoubleType(),
                [("offset", IntegerType()), ("size", IntegerType())],
            ),
        }
        self.modules["math"] = math

        # ELF module
        elf = ModuleDefinition(name="elf")
        elf.attributes = {
            "type": IntegerType(),
            "machine": IntegerType(),
            "entry_point": IntegerType(),
            "sections": ArrayType(
                StructType(
                    {
                        "name": StringType(),
                        "type": IntegerType(),
                        "address": IntegerType(),
                        "size": IntegerType(),
                        "offset": IntegerType(),
                    },
                ),
            ),
            "segments": ArrayType(
                StructType(
                    {
                        "type": IntegerType(),
                        "offset": IntegerType(),
                        "virtual_address": IntegerType(),
                        "physical_address": IntegerType(),
                        "file_size": IntegerType(),
                        "memory_size": IntegerType(),
                    },
                ),
            ),
        }
        self.modules["elf"] = elf

        # Hash module
        hash_mod = ModuleDefinition(name="hash")
        hash_mod.functions = {
            "md5": FunctionDefinition(
                "md5",
                StringType(),
                [("offset", IntegerType()), ("size", IntegerType())],
            ),
            "sha1": FunctionDefinition(
                "sha1",
                StringType(),
                [("offset", IntegerType()), ("size", IntegerType())],
            ),
            "sha256": FunctionDefinition(
                "sha256",
                StringType(),
                [("offset", IntegerType()), ("size", IntegerType())],
            ),
            "crc32": FunctionDefinition(
                "crc32",
                IntegerType(),
                [("offset", IntegerType()), ("size", IntegerType())],
            ),
        }
        self.modules["hash"] = hash_mod

        # Dotnet module
        dotnet = ModuleDefinition(name="dotnet")
        dotnet.attributes = {
            "version": StringType(),
            "module_name": StringType(),
            "assembly": DictionaryType(StringType(), StringType()),
            "resources": ArrayType(DictionaryType(StringType(), IntegerType())),
            "streams": ArrayType(DictionaryType(StringType(), IntegerType())),
        }
        self.modules["dotnet"] = dotnet

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
        from yaraast.types.type_system import (
            AnyType,
            ArrayType,
            BooleanType,
            DictionaryType,
            FloatType,
            IntegerType,
            StringType,
            StructType,
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
                    name = param.get("name", "param")
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
