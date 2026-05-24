"""Builtin module definitions for YARA type system."""

from __future__ import annotations

from typing import Any

from yaraast.types.module_contracts import FunctionDefinition, ModuleDefinition

# Declarative module specs: type strings -> actual types resolved at load time.
# "i"=int, "s"=str, "b"=bool, "d"=double
# Compound: ("array", elem), ("dict", k, v), ("struct", {fields})
# Functions: (return_type, [(param_name, param_type), ...], min_parameters?, variadic?)

_MODULE_SPECS: dict[str, dict[str, Any]] = {
    "pe": {
        "attrs": {
            "machine": "i",
            "number_of_sections": "i",
            "timestamp": "i",
            "characteristics": "i",
            "entry_point": "i",
            "entry_point_raw": "i",
            "image_base": "i",
            "sections": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "full_name": "s",
                        "virtual_address": "i",
                        "virtual_size": "i",
                        "raw_data_offset": "i",
                        "raw_data_size": "i",
                        "characteristics": "i",
                    },
                ),
            ),
            "version_info": ("dict", "s", "s"),
            "number_of_resources": "i",
            "resource_timestamp": "i",
            "is_pe": "b",
        },
        "funcs": {
            "imphash": ("s", []),
            "section_index": ("i", [("name", "s")]),
            "exports": ("b", [("name_or_ordinal", "scalar")]),
            "imports": (
                "b",
                [
                    ("dll_or_descriptor", "scalar"),
                    ("function_or_ordinal", "scalar"),
                    ("function_or_ordinal", "scalar"),
                ],
                1,
            ),
            "locale": ("b", [("locale", "i")]),
            "language": ("b", [("lang", "i")]),
            "is_dll": ("b", []),
            "is_64bit": ("b", []),
            "is_32bit": ("b", []),
            "rva_to_offset": ("i", [("rva", "i")]),
        },
    },
    "math": {
        "funcs": {
            "abs": ("i", [("x", "i")]),
            "min": ("i", [("a", "i"), ("b", "i")]),
            "max": ("i", [("a", "i"), ("b", "i")]),
            "to_string": ("s", [("n", "i"), ("base", "i")], 1),
            "to_number": ("i", [("b", "b")]),
            "entropy": ("d", [("value_or_offset", "s"), ("size", "i")], 1),
            "mean": ("d", [("value_or_offset", "s"), ("size", "i")], 1),
            "deviation": ("d", [("value_or_offset", "s"), ("size_or_mean", "d"), ("mean", "d")], 2),
            "serial_correlation": ("d", [("value_or_offset", "s"), ("size", "i")], 1),
            "monte_carlo_pi": ("d", [("value_or_offset", "s"), ("size", "i")], 1),
            "count": ("i", [("byte", "i"), ("offset", "i"), ("size", "i")]),
            "percentage": ("d", [("byte", "i"), ("offset", "i"), ("size", "i")]),
            "mode": ("i", [("offset", "i"), ("size", "i")]),
        },
    },
    "elf": {
        "attrs": {
            "type": "i",
            "machine": "i",
            "entry_point": "i",
            "sh_offset": "i",
            "sh_entry_size": "i",
            "ph_offset": "i",
            "ph_entry_size": "i",
            "number_of_sections": "i",
            "number_of_segments": "i",
            "sections": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "type": "i",
                        "flags": "i",
                        "address": "i",
                        "size": "i",
                        "offset": "i",
                    },
                ),
            ),
            "segments": (
                "array",
                (
                    "struct",
                    {
                        "type": "i",
                        "flags": "i",
                        "offset": "i",
                        "virtual_address": "i",
                        "physical_address": "i",
                        "file_size": "i",
                        "memory_size": "i",
                        "alignment": "i",
                    },
                ),
            ),
            "symtab": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "value": "i",
                        "size": "i",
                        "type": "i",
                        "bind": "i",
                        "shndx": "i",
                    },
                ),
            ),
            "dynsym": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "value": "i",
                        "size": "i",
                        "type": "i",
                        "bind": "i",
                        "shndx": "i",
                    },
                ),
            ),
            "dynamic": (
                "array",
                (
                    "struct",
                    {
                        "type": "i",
                        "val": "i",
                    },
                ),
            ),
        },
    },
    "hash": {
        "funcs": {
            "md5": ("s", [("value_or_offset", "s"), ("size", "i")], 1),
            "sha1": ("s", [("value_or_offset", "s"), ("size", "i")], 1),
            "sha256": ("s", [("value_or_offset", "s"), ("size", "i")], 1),
            "checksum32": ("i", [("value_or_offset", "s"), ("size", "i")], 1),
            "crc32": ("i", [("value_or_offset", "s"), ("size", "i")], 1),
        },
    },
    "dotnet": {
        "attrs": {
            "version": "s",
            "module_name": "s",
            "number_of_streams": "i",
            "number_of_guids": "i",
            "number_of_resources": "i",
            "number_of_user_strings": "i",
            "assembly": (
                "struct",
                {
                    "name": "s",
                    "culture": "s",
                    "version": (
                        "struct",
                        {
                            "major": "i",
                            "minor": "i",
                        },
                    ),
                },
            ),
            "resources": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "offset": "i",
                        "length": "i",
                    },
                ),
            ),
            "streams": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "offset": "i",
                        "size": "i",
                    },
                ),
            ),
        },
    },
    "time": {"funcs": {"now": ("i", [])}},
    "console": {"funcs": {"log": ("b", [("message", "scalar"), ("value", "scalar")], 1)}},
    "string": {
        "funcs": {
            "to_int": ("i", [("s", "s"), ("base", "i")], 1),
            "length": ("i", [("s", "s")]),
        },
    },
    "cuckoo": {
        "attrs": {
            "network": ("struct", {}),
            "filesystem": ("struct", {}),
            "registry": ("struct", {}),
            "sync": ("struct", {}),
        },
        "funcs": {
            "network.http_request": ("b", [("regexp", "r")]),
            "network.http_get": ("b", [("regexp", "r")]),
            "network.http_post": ("b", [("regexp", "r")]),
            "network.http_user_agent": ("b", [("regexp", "r")]),
            "network.dns_lookup": ("b", [("regexp", "r")]),
            "network.host": ("b", [("regexp", "r")]),
            "network.tcp": ("b", [("regexp", "r"), ("port", "i")]),
            "network.udp": ("b", [("regexp", "r"), ("port", "i")]),
            "registry.key_access": ("b", [("regexp", "r")]),
            "filesystem.file_access": ("b", [("regexp", "r")]),
            "sync.mutex": ("b", [("regexp", "r")]),
        },
    },
    "magic": {"attrs": {"mime_type": "s", "type": "s"}},
    "vt": {"attrs": {"metadata": ("struct", {})}},
}


def _resolve_type(spec):
    """Map a type spec to an actual YaraType instance."""
    from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
    from yaraast.types._registry_primitives import (
        BooleanType,
        DoubleType,
        IntegerType,
        RegexType,
        ScalarType,
        StringType,
    )

    primitives = {
        "i": IntegerType,
        "s": StringType,
        "b": BooleanType,
        "d": DoubleType,
        "r": RegexType,
        "scalar": ScalarType,
    }
    if isinstance(spec, str):
        return primitives[spec]()
    tag = spec[0]
    if tag == "array":
        return ArrayType(_resolve_type(spec[1]))
    if tag == "dict":
        return DictionaryType(_resolve_type(spec[1]), _resolve_type(spec[2]))
    if tag == "struct":
        return StructType({k: _resolve_type(v) for k, v in spec[1].items()})
    return IntegerType()


def load_builtin_modules() -> dict[str, ModuleDefinition]:
    """Create builtin module definitions from declarative specs."""
    modules: dict[str, ModuleDefinition] = {}
    for name, spec in _MODULE_SPECS.items():
        mod = ModuleDefinition(name=name)
        if "attrs" in spec:
            mod.attributes = {k: _resolve_type(v) for k, v in spec["attrs"].items()}
        if "funcs" in spec:
            mod.functions = {
                fname: FunctionDefinition(
                    fname,
                    _resolve_type(fspec[0]),
                    [(p[0], _resolve_type(p[1])) for p in fspec[1]],
                    fspec[2] if len(fspec) > 2 else None,
                    fspec[3] if len(fspec) > 3 else False,
                )
                for fname, fspec in spec["funcs"].items()
            }
        modules[name] = mod
    return modules
