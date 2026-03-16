"""Builtin module definitions for YARA type system."""

from __future__ import annotations

from yaraast.types.module_contracts import FunctionDefinition, ModuleDefinition


def load_builtin_modules() -> dict[str, ModuleDefinition]:
    """Create builtin module definitions."""
    from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
    from yaraast.types._registry_primitives import BooleanType, DoubleType, IntegerType, StringType

    modules: dict[str, ModuleDefinition] = {}

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
        "is_dll": FunctionDefinition("is_dll", BooleanType()),
        "is_64bit": FunctionDefinition("is_64bit", BooleanType()),
        "is_32bit": FunctionDefinition("is_32bit", BooleanType()),
        "rva_to_offset": FunctionDefinition(
            "rva_to_offset",
            IntegerType(),
            [("rva", IntegerType())],
        ),
    }
    modules["pe"] = pe

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
    modules["math"] = math

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
    modules["elf"] = elf

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
    modules["hash"] = hash_mod

    dotnet = ModuleDefinition(name="dotnet")
    dotnet.attributes = {
        "version": StringType(),
        "module_name": StringType(),
        "assembly": DictionaryType(StringType(), StringType()),
        "resources": ArrayType(DictionaryType(StringType(), IntegerType())),
        "streams": ArrayType(DictionaryType(StringType(), IntegerType())),
    }
    modules["dotnet"] = dotnet

    # Additional YARA modules

    time_mod = ModuleDefinition(name="time")
    time_mod.attributes = {"now": IntegerType()}
    modules["time"] = time_mod

    console_mod = ModuleDefinition(name="console")
    console_mod.functions = {
        "log": FunctionDefinition("log", BooleanType(), [("message", StringType())]),
    }
    modules["console"] = console_mod

    string_mod = ModuleDefinition(name="string")
    string_mod.functions = {
        "to_int": FunctionDefinition("to_int", IntegerType(), [("s", StringType())]),
        "length": FunctionDefinition("length", IntegerType(), [("s", StringType())]),
    }
    modules["string"] = string_mod

    cuckoo_mod = ModuleDefinition(name="cuckoo")
    cuckoo_mod.attributes = {
        "network": StructType({}),
        "filesystem": StructType({}),
        "registry": StructType({}),
        "sync": StructType({}),
    }
    modules["cuckoo"] = cuckoo_mod

    magic_mod = ModuleDefinition(name="magic")
    magic_mod.attributes = {
        "mime_type": StringType(),
        "type": StringType(),
    }
    modules["magic"] = magic_mod

    vt_mod = ModuleDefinition(name="vt")
    vt_mod.attributes = {
        "metadata": StructType({}),
    }
    modules["vt"] = vt_mod

    return modules
