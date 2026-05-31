"""Additional real coverage for types.module_loader."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from yaraast.types.module_loader import ModuleLoader, ModuleSpecError
from yaraast.types.type_system import AnyType, BooleanType, IntegerType


def test_module_loader_rejects_invalid_json_specs(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{ not valid json", encoding="utf-8")

    os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"] = str(invalid_json)
    try:
        with pytest.raises(ModuleSpecError, match="Invalid JSON"):
            ModuleLoader()
    finally:
        del os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"]


def test_module_loader_rejects_malformed_module_sections(tmp_path: Path) -> None:
    bad_module = tmp_path / "bad_module.json"
    bad_module.write_text(
        json.dumps(
            {
                "name": "bad_module",
                "attributes": ["not-a-dict"],
            }
        ),
        encoding="utf-8",
    )

    os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"] = str(tmp_path)
    try:
        with pytest.raises(ModuleSpecError, match="attributes must be an object"):
            ModuleLoader()
    finally:
        del os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"]

    loader = ModuleLoader()
    assert isinstance(loader._parse_type({"type": "mystery"}), AnyType)


def test_module_loader_rejects_invalid_module_name_without_partial_load(tmp_path: Path) -> None:
    json_path = tmp_path / "modules.json"
    json_path.write_text(
        json.dumps(
            [
                {"name": "first", "attributes": {"enabled": "bool"}},
                {"name": ["bad"], "attributes": {"broken": "int"}},
                {"name": "last", "constants": {"K": "int"}},
            ]
        ),
        encoding="utf-8",
    )

    os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"] = str(json_path)
    try:
        with pytest.raises(ModuleSpecError, match="Module name must be a non-empty string"):
            ModuleLoader()
    finally:
        del os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"]

    loader = ModuleLoader()
    before = dict(loader.modules)
    with pytest.raises(ModuleSpecError, match="Module name must be a non-empty string"):
        loader._load_module_file(json_path)
    assert loader.modules == before


def test_module_loader_rejects_unreadable_module_specs(tmp_path: Path) -> None:
    loader = ModuleLoader()

    with pytest.raises(ModuleSpecError, match="Unable to read module specification"):
        loader._load_module_file(tmp_path)


def test_module_loader_parses_parameter_forms_and_lists_modules(tmp_path: Path) -> None:
    module_json = {
        "name": "calc",
        "functions": {
            "one": {
                "return": "bool",
                "parameters": ["x", {"name": "flag", "type": "bool"}],
            }
        },
        "constants": {"K": "unknown_type"},
    }

    json_path = tmp_path / "calc.json"
    json_path.write_text(json.dumps(module_json), encoding="utf-8")

    os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"] = str(json_path)
    try:
        loader = ModuleLoader()
    finally:
        del os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"]

    assert loader.list_modules() == ["calc"]
    calc = loader.get_module("calc")
    assert calc is not None
    assert len(calc.functions["one"].parameters) == 2
    assert calc.functions["one"].parameters[0][0] == "x"
    assert isinstance(calc.functions["one"].parameters[0][1], AnyType)
    assert calc.functions["one"].parameters[1][0] == "flag"
    assert isinstance(calc.functions["one"].parameters[1][1], BooleanType)
    assert isinstance(calc.constants["K"], AnyType)

    parsed = loader._parse_module(
        "manual",
        {
            "name": "manual",
            "attributes": {"enabled": "bool"},
            "functions": {"two": {"return": "int", "parameters": {"n": "int"}}},
        },
    )
    assert parsed is not None
    assert isinstance(parsed.attributes["enabled"], BooleanType)
    assert parsed.functions["two"].parameters == [("n", IntegerType())]


def test_module_loader_normalizes_invalid_parameter_names() -> None:
    loader = ModuleLoader()

    parameters = loader._parse_parameters(
        [
            {"name": ["bad"], "type": "int"},
            {"name": "", "type": "bool"},
            {"type": "string"},
        ]
    )

    assert [name for name, _type in parameters] == ["param_0", "param_1", "param_2"]


def test_module_loader_normalizes_invalid_function_arity_metadata() -> None:
    loader = ModuleLoader()

    module = loader._parse_module(
        "manual",
        {
            "name": "manual",
            "functions": {
                "f": {
                    "return": "bool",
                    "parameters": ["x"],
                    "min_parameters": "bad",
                    "variadic": "yes",
                }
            },
        },
    )

    assert module is not None
    func = module.functions["f"]
    assert func.min_parameters is None
    assert func.variadic is False


def test_module_loader_degrades_malformed_complex_type_without_aborting_module() -> None:
    loader = ModuleLoader()

    module = loader._parse_module(
        "manual",
        {
            "name": "manual",
            "attributes": {
                "broken": {"type": "struct", "fields": ["bad"]},
                "ok": "int",
            },
        },
    )

    assert module is not None
    assert isinstance(module.attributes["broken"], AnyType)
    assert isinstance(module.attributes["ok"], IntegerType)


def test_module_loader_rejects_malformed_parameter_lists() -> None:
    loader = ModuleLoader()

    with pytest.raises(TypeError, match="parameters must be strings or objects"):
        loader._parse_parameters(["ok", 1])

    with pytest.raises(TypeError, match="parameters must be a list or object"):
        loader._parse_parameters("not-a-parameter-list")
