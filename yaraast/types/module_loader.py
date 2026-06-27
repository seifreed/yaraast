"""Module loader for loading YARA module definitions from JSON."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from yaraast.types._registry_base import YaraType
from yaraast.types.module_contracts import FunctionDefinition, ModuleDefinition
from yaraast.types.module_definitions import load_builtin_modules
from yaraast.types.type_environment import _normalize_identifier


class ModuleSpecError(ValueError):
    """Raised when a module specification file cannot be loaded."""


def _path_access_error(path: Path) -> ModuleSpecError:
    msg = f"path could not be accessed: {path}"
    return ModuleSpecError(msg)


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _normalize_module_name(name: object) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Module name must be a non-empty string")
    return _normalize_identifier(name, "Module name", "module")


def _require_module_lookup_name(name: str) -> str:
    if not isinstance(name, str):
        msg = "Module lookup name must be a string"
        raise TypeError(msg)
    if not name.strip():
        msg = "Module lookup name cannot be empty"
        raise ValueError(msg)
    return name


def _normalize_member_name(name: object, kind: str) -> str:
    if not isinstance(name, str) or not name.strip():
        msg = f"Module {kind} names must be non-empty strings"
        raise ValueError(msg)
    return _normalize_identifier(name, f"Module {kind} name", f"module {kind}")


def _normalize_function_name(name: object) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Module function names must be non-empty strings")
    parts = name.split(".")
    if any(not part.strip() for part in parts):
        msg = f"Invalid module function identifier: {name}"
        raise ValueError(msg)
    return ".".join(
        _normalize_identifier(part, "Module function name", "module function") for part in parts
    )


def _normalize_parameter_name(name: object, index: int) -> str:
    if isinstance(name, str) and name.strip():
        return name
    return f"param_{index}"


def _normalize_min_parameters(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _normalize_variadic(value: object) -> bool:
    return value if isinstance(value, bool) else False


def _validate_function_arity_metadata(
    func_name: str,
    min_parameters: int | None,
    parameter_count: int,
    *,
    variadic: bool,
) -> None:
    if min_parameters is None or variadic or min_parameters <= parameter_count:
        return
    msg = f"Module function '{func_name}' min_parameters cannot exceed parameter count"
    raise ValueError(msg)


def _module_spec_path_entries(env_name: str) -> list[str]:
    raw_value = os.environ.get(env_name)
    if not raw_value:
        return []
    entries = raw_value.split(os.pathsep)
    if any(not entry.strip() for entry in entries):
        msg = f"{env_name} must not contain empty path entries"
        raise ModuleSpecError(msg)
    return entries


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
        module_paths.extend(_module_spec_path_entries("YARAAST_MODULE_SPEC_PATH"))

        # YARAAST_MODULE_SPEC_PATH_EXCLUSIVE - exclusive paths (ignore builtins)
        exclusive_mode = False
        if os.environ.get("YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"):
            exclusive_mode = True
            self.modules.clear()  # Clear builtin modules
            module_paths.extend(
                _module_spec_path_entries("YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"),
            )

        # Default location (only if not in exclusive mode)
        if not exclusive_mode:
            default_path = Path(__file__).parent / "modules"
            if _path_exists(default_path) and str(default_path) not in module_paths:
                module_paths.append(str(default_path))

        # Load modules from all paths
        for path_str in module_paths:
            path = Path(path_str)
            if _path_is_symlink(path):
                msg = f"Module specification path '{path}' must not be a symlink"
                raise ModuleSpecError(msg)
            if _path_is_file(path) and path.suffix == ".json":
                self._load_module_file(path)
            elif _path_is_dir(path):
                for json_file in path.glob("*.json"):
                    if _path_is_symlink(json_file):
                        continue
                    self._load_module_file(json_file)
            else:
                msg = (
                    f"Module specification path '{path}' must be an existing JSON file or directory"
                )
                raise ModuleSpecError(msg)

    def _load_module_file(self, path: Path) -> None:
        """Load a single module definition from JSON file."""
        try:
            with Path(path).open(encoding="utf-8") as f:
                data = json.load(f)
        except UnicodeDecodeError as exc:
            msg = f"Module specification '{path}' must contain valid UTF-8 text"
            raise ModuleSpecError(msg) from exc
        except json.JSONDecodeError as exc:
            msg = f"Invalid JSON in module specification '{path}': {exc.msg}"
            raise ModuleSpecError(msg) from exc
        except OSError as exc:
            msg = f"Unable to read module specification '{path}': {exc}"
            raise ModuleSpecError(msg) from exc

        loaded_modules: list[ModuleDefinition] = []
        try:
            if isinstance(data, dict):
                # Single module in file
                module = self._parse_module(path.stem, data)
                loaded_modules.append(module)
            elif isinstance(data, list):
                # Multiple modules in file
                for index, module_data in enumerate(data):
                    if not isinstance(module_data, dict):
                        msg = f"Module specification list item {index} must be an object"
                        raise ValueError(msg)
                    module = self._parse_module(module_data.get("name"), module_data)
                    loaded_modules.append(module)
            else:
                msg = "Module specification must be a JSON object or list of objects"
                raise ValueError(msg)
        except (ValueError, TypeError) as exc:
            msg = f"Invalid module specification '{path}': {exc}"
            raise ModuleSpecError(msg) from exc

        for module in loaded_modules:
            self.modules[module.name] = module

    def _parse_module(self, name: object, data: dict[str, Any]) -> ModuleDefinition:
        """Parse module definition from JSON data."""
        module = ModuleDefinition(name=_normalize_module_name(data.get("name", name)))

        # Parse attributes
        if "attributes" in data:
            attributes = data["attributes"]
            if not isinstance(attributes, dict):
                raise TypeError("Module attributes must be an object")
            for attr_name, attr_type in attributes.items():
                attr_name = _normalize_member_name(attr_name, "attribute")
                module.attributes[attr_name] = self._parse_type(attr_type)

        # Parse functions
        if "functions" in data:
            functions = data["functions"]
            if not isinstance(functions, dict):
                raise TypeError("Module functions must be an object")
            for func_name, func_data in functions.items():
                func_name = _normalize_function_name(func_name)
                if not isinstance(func_data, dict):
                    raise TypeError(f"Module function '{func_name}' must be an object")
                parameters = self._parse_parameters(func_data.get("parameters", []))
                min_parameters = _normalize_min_parameters(func_data.get("min_parameters"))
                variadic = _normalize_variadic(func_data.get("variadic"))
                _validate_function_arity_metadata(
                    func_name,
                    min_parameters,
                    len(parameters),
                    variadic=variadic,
                )
                func_def = FunctionDefinition(
                    name=func_name,
                    return_type=self._parse_type(
                        func_data.get("return", "any"),
                    ),
                    parameters=parameters,
                    min_parameters=min_parameters,
                    variadic=variadic,
                )
                module.functions[func_name] = func_def

        # Parse constants
        if "constants" in data:
            constants = data["constants"]
            if not isinstance(constants, dict):
                raise TypeError("Module constants must be an object")
            for const_name, const_type in constants.items():
                const_name = _normalize_member_name(const_name, "constant")
                module.constants[const_name] = self._parse_type(const_type)

        return module

    def _parse_type(self, type_str: str | dict[str, Any]) -> YaraType:
        """Parse type from string or dict representation."""
        from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
        from yaraast.types._registry_primitives import (
            AnyType,
            BooleanType,
            FloatType,
            IntegerType,
            RegexType,
            ScalarType,
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
                "regex": RegexType(),
                "regexp": RegexType(),
                "r": RegexType(),
                "scalar": ScalarType(),
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
                raw_fields = type_str.get("fields", {})
                if not isinstance(raw_fields, dict):
                    return AnyType()
                fields: dict[str, YaraType] = {}
                for field_name, field_type in raw_fields.items():
                    field_name = _normalize_member_name(field_name, "struct field")
                    fields[field_name] = self._parse_type(field_type)
                return StructType(fields)

        return AnyType()

    def _parse_parameters(
        self,
        params: object,
    ) -> list[tuple[str, YaraType]]:
        """Parse function parameters."""
        result: list[tuple[str, YaraType]] = []

        if isinstance(params, list):
            # List of parameter names (assume any type)
            for param in params:
                if isinstance(param, str):
                    result.append(
                        (
                            _normalize_parameter_name(param, len(result)),
                            self._parse_type("any"),
                        )
                    )
                elif isinstance(param, dict):
                    name = _normalize_parameter_name(param.get("name"), len(result))
                    type_ = self._parse_type(param.get("type", "any"))
                    result.append((name, type_))
                else:
                    raise TypeError("Module function parameters must be strings or objects")

        elif isinstance(params, dict):
            # Dict of name: type
            for name, type_str in params.items():
                result.append(
                    (
                        _normalize_parameter_name(name, len(result)),
                        self._parse_type(type_str),
                    )
                )
        else:
            raise TypeError("Module function parameters must be a list or object")

        return result

    def get_module(self, name: str) -> ModuleDefinition | None:
        """Get module definition by name."""
        name = _require_module_lookup_name(name)
        return self.modules.get(name)

    def list_modules(self) -> list[str]:
        """Return the names of all loaded modules, sorted."""
        return sorted(self.modules)
