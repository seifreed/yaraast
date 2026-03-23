"""Builtin module definitions for YARA type system."""

from __future__ import annotations

from typing import Any

from yaraast.types.module_contracts import FunctionDefinition, ModuleDefinition

# Declarative module specs: type strings -> actual types resolved at load time.
# "i"=int, "s"=str, "b"=bool, "d"=double
# Compound: ("array", elem), ("dict", k, v), ("struct", {fields})
# Functions: (return_type, [(param_name, param_type), ...])

_MODULE_SPECS: dict[str, dict[str, Any]] = {
    "pe": {
        "attrs": {
            "machine": "i",
            "number_of_sections": "i",
            "timestamp": "i",
            "characteristics": "i",
            "entry_point": "i",
            "image_base": "i",
            "sections": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "virtual_address": "i",
                        "virtual_size": "i",
                        "raw_size": "i",
                        "characteristics": "i",
                    },
                ),
            ),
            "version_info": ("dict", "s", "s"),
            "number_of_resources": "i",
            "resource_timestamp": "i",
            "imports": ("array", "s"),
            "exports": ("array", "s"),
            "is_pe": "b",
            "is_dll": "b",
            "is_32bit": "b",
            "is_64bit": "b",
        },
        "funcs": {
            "imphash": ("s", []),
            "section_index": ("i", [("name", "s")]),
            "exports": ("b", [("name", "s")]),
            "imports": ("b", [("dll", "s"), ("function", "s")]),
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
            "to_string": ("s", [("n", "i"), ("base", "i")]),
            "to_number": ("i", [("s", "s")]),
            "log": ("d", [("x", "d")]),
            "log2": ("d", [("x", "d")]),
            "log10": ("d", [("x", "d")]),
            "sqrt": ("d", [("x", "d")]),
            "entropy": ("d", [("offset", "i"), ("size", "i")]),
        },
    },
    "elf": {
        "attrs": {
            "type": "i",
            "machine": "i",
            "entry_point": "i",
            "sections": (
                "array",
                (
                    "struct",
                    {
                        "name": "s",
                        "type": "i",
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
                        "offset": "i",
                        "virtual_address": "i",
                        "physical_address": "i",
                        "file_size": "i",
                        "memory_size": "i",
                    },
                ),
            ),
        },
    },
    "hash": {
        "funcs": {
            "md5": ("s", [("offset", "i"), ("size", "i")]),
            "sha1": ("s", [("offset", "i"), ("size", "i")]),
            "sha256": ("s", [("offset", "i"), ("size", "i")]),
            "crc32": ("i", [("offset", "i"), ("size", "i")]),
        },
    },
    "dotnet": {
        "attrs": {
            "version": "s",
            "module_name": "s",
            "assembly": ("dict", "s", "s"),
            "resources": ("array", ("dict", "s", "i")),
            "streams": ("array", ("dict", "s", "i")),
        },
    },
    "time": {"attrs": {"now": "i"}},
    "console": {"funcs": {"log": ("b", [("message", "s")])}},
    "string": {
        "funcs": {
            "to_int": ("i", [("s", "s")]),
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
    },
    "magic": {"attrs": {"mime_type": "s", "type": "s"}},
    "vt": {"attrs": {"metadata": ("struct", {})}},
}


def _resolve_type(spec):
    """Map a type spec to an actual YaraType instance."""
    from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
    from yaraast.types._registry_primitives import BooleanType, DoubleType, IntegerType, StringType

    primitives = {"i": IntegerType, "s": StringType, "b": BooleanType, "d": DoubleType}
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
                )
                for fname, fspec in spec["funcs"].items()
            }
        modules[name] = mod
    return modules
