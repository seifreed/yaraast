"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Regression coverage for yaraast/types/module_loader.py.

Target lines at the time of writing (93.16 %):
  28-29   _path_exists OSError branch
  42-43   _path_is_dir OSError branch
  74-75   _normalize_function_name dotted-segment empty/whitespace guard
  153->157 branch: default_path already in module_paths (skip append)
  195-196 list item is not a dict
  200-201 JSON root is neither dict nor list
  226     functions section is not a dict (TypeError)
  230     individual function value is not a dict (TypeError)
  255     constants section is not a dict (TypeError)
  300->319 _parse_type receives a value that is neither str nor dict
  366     list_modules() public method

Every test exercises real production code.  No mocks, no stubs, no patch
of the module under test.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yaraast.types.module_loader import (
    ModuleLoader,
    ModuleSpecError,
    _normalize_function_name,
    _path_access_error,
    _path_exists,
    _path_is_dir,
)
from yaraast.types.type_system import AnyType

# ---------------------------------------------------------------------------
# Helper: derive the real default modules directory from the installed package
# ---------------------------------------------------------------------------


def _default_modules_dir() -> str:
    """Return the absolute path the ModuleLoader uses as its built-in default."""
    spec = importlib.util.find_spec("yaraast.types.module_loader")
    assert spec is not None and spec.origin is not None
    return str(Path(spec.origin).parent / "modules")


# ---------------------------------------------------------------------------
# Lines 28-29  _path_exists — OSError branch
# ---------------------------------------------------------------------------


def test_path_exists_oserror_raises_module_spec_error() -> None:
    """
    _path_exists must convert an OSError from Path.exists() into a
    ModuleSpecError with the human-readable "path could not be accessed"
    message.  A pathname longer than NAME_MAX (255 on macOS/Linux) triggers
    a real ENAMETOOLONG OSError without any filesystem side-effects.
    """
    oversized = Path("a" * 5000)
    with pytest.raises(ModuleSpecError, match="path could not be accessed"):
        _path_exists(oversized)


# ---------------------------------------------------------------------------
# Lines 42-43  _path_is_dir — OSError branch
# ---------------------------------------------------------------------------


def test_path_is_dir_oserror_raises_module_spec_error() -> None:
    """
    _path_is_dir must convert an OSError from Path.is_dir() into a
    ModuleSpecError.  The same ENAMETOOLONG trigger is used.
    """
    oversized = Path("b" * 5000)
    with pytest.raises(ModuleSpecError, match="path could not be accessed"):
        _path_is_dir(oversized)


# ---------------------------------------------------------------------------
# Sanity: _path_access_error constructs the correct exception type and message
# ---------------------------------------------------------------------------


def test_path_access_error_returns_module_spec_error() -> None:
    """_path_access_error must return a ModuleSpecError with the path embedded."""
    p = Path("/some/path")
    exc = _path_access_error(p)
    assert isinstance(exc, ModuleSpecError)
    assert "/some/path" in str(exc)


# ---------------------------------------------------------------------------
# Lines 74-75  _normalize_function_name — dotted-segment empty guard
# ---------------------------------------------------------------------------


def test_normalize_function_name_rejects_dotted_name_with_empty_segment() -> None:
    """
    A dotted function name where one segment is whitespace-only must raise
    ValueError with an 'Invalid module function identifier' message.
    The segment check is distinct from the top-level empty-name check and
    lives at lines 73-75.
    """
    with pytest.raises(ValueError, match="Invalid module function identifier"):
        _normalize_function_name("network. .send")


def test_normalize_function_name_rejects_dotted_name_with_trailing_dot() -> None:
    """A trailing dot produces an empty segment that must be rejected."""
    with pytest.raises(ValueError, match="Invalid module function identifier"):
        _normalize_function_name("network.")


# ---------------------------------------------------------------------------
# Branch 153->157  default_path already in module_paths — skip append
# ---------------------------------------------------------------------------


def test_load_json_modules_skips_duplicate_default_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When YARAAST_MODULE_SPEC_PATH is explicitly set to the same directory that
    ModuleLoader would add as the built-in default, the loader must not add it
    a second time (branch 153->157 in _load_json_modules).  Modules should
    still load exactly once — verified by checking list_modules() output is
    identical to a baseline loader.
    """
    default_dir = _default_modules_dir()

    # Baseline: load with no overrides so we know what builtins are expected
    baseline = ModuleLoader().list_modules()

    # Exercise the branch: SPEC_PATH points at the same default dir
    monkeypatch.setenv("YARAAST_MODULE_SPEC_PATH", default_dir)
    loader = ModuleLoader()

    assert loader.list_modules() == baseline


# ---------------------------------------------------------------------------
# Lines 195-196  list item inside a JSON array is not a dict
# ---------------------------------------------------------------------------


def test_load_module_file_rejects_non_dict_list_item(tmp_path: Path) -> None:
    """
    When a JSON file contains a top-level array and one element is not a
    JSON object, _load_module_file must raise ModuleSpecError mentioning the
    item index.
    """
    spec_file = tmp_path / "bad_list.json"
    spec_file.write_text(
        json.dumps([{"name": "valid_mod", "attributes": {}}, "not-an-object"]),
        encoding="utf-8",
    )
    loader = ModuleLoader()
    with pytest.raises(ModuleSpecError, match="list item 1 must be an object"):
        loader._load_module_file(spec_file)


# ---------------------------------------------------------------------------
# Lines 200-201  JSON root is neither dict nor list
# ---------------------------------------------------------------------------


def test_load_module_file_rejects_root_scalar(tmp_path: Path) -> None:
    """
    A JSON file whose root value is a scalar (not an object or array) must
    cause _load_module_file to raise ModuleSpecError indicating the spec
    must be an object or list.
    """
    spec_file = tmp_path / "scalar_root.json"
    spec_file.write_text(json.dumps(42), encoding="utf-8")
    loader = ModuleLoader()
    with pytest.raises(
        ModuleSpecError,
        match="Module specification must be a JSON object or list of objects",
    ):
        loader._load_module_file(spec_file)


def test_load_module_file_rejects_root_string(tmp_path: Path) -> None:
    """A JSON root string is also invalid — exercises the same scalar branch."""
    spec_file = tmp_path / "string_root.json"
    spec_file.write_text(json.dumps("just-a-string"), encoding="utf-8")
    loader = ModuleLoader()
    with pytest.raises(
        ModuleSpecError,
        match="Module specification must be a JSON object or list of objects",
    ):
        loader._load_module_file(spec_file)


# ---------------------------------------------------------------------------
# Line 226  functions section is not a dict
# ---------------------------------------------------------------------------


def test_parse_module_rejects_functions_as_list() -> None:
    """
    When the 'functions' key maps to a JSON array rather than an object,
    _parse_module must raise TypeError (re-raised as ModuleSpecError by the
    calling layer, but the underlying TypeError is the target line 226).
    """
    loader = ModuleLoader()
    with pytest.raises(TypeError, match="Module functions must be an object"):
        loader._parse_module(
            "m",
            {"name": "m", "functions": ["not", "a", "dict"]},
        )


# ---------------------------------------------------------------------------
# Line 230  individual function value is not a dict
# ---------------------------------------------------------------------------


def test_parse_module_rejects_function_value_as_scalar() -> None:
    """
    When a function name maps to a non-dict value (e.g. a string), the
    function-level type check at line 229-230 must raise TypeError.
    """
    loader = ModuleLoader()
    with pytest.raises(TypeError, match="must be an object"):
        loader._parse_module(
            "m",
            {"name": "m", "functions": {"do_thing": "not-a-dict"}},
        )


def test_parse_module_rejects_function_value_as_integer() -> None:
    """Integer function values also trigger line 230."""
    loader = ModuleLoader()
    with pytest.raises(TypeError, match="must be an object"):
        loader._parse_module(
            "m",
            {"name": "m", "functions": {"compute": 99}},
        )


# ---------------------------------------------------------------------------
# Line 255  constants section is not a dict
# ---------------------------------------------------------------------------


def test_parse_module_rejects_constants_as_list() -> None:
    """
    When 'constants' maps to a list rather than an object, the type guard
    at line 254-255 must raise TypeError.
    """
    loader = ModuleLoader()
    with pytest.raises(TypeError, match="Module constants must be an object"):
        loader._parse_module(
            "m",
            {"name": "m", "constants": [1, 2, 3]},
        )


def test_parse_module_rejects_constants_as_string() -> None:
    """A string value for constants also hits line 255."""
    loader = ModuleLoader()
    with pytest.raises(TypeError, match="Module constants must be an object"):
        loader._parse_module(
            "m",
            {"name": "m", "constants": "MAX=10"},
        )


# ---------------------------------------------------------------------------
# Branch 300->319  _parse_type with a value that is neither str nor dict
# ---------------------------------------------------------------------------


def test_parse_type_with_integer_returns_any_type() -> None:
    """
    _parse_type must gracefully degrade to AnyType when it receives a value
    that is neither a string nor a dict (e.g. an integer).  This exercises
    the fallthrough at line 319.
    """
    loader = ModuleLoader()
    result = loader._parse_type(42)  # type: ignore[arg-type]
    assert isinstance(result, AnyType)


def test_parse_type_with_none_returns_any_type() -> None:
    """None is not str or dict — must fall through to the AnyType return."""
    loader = ModuleLoader()
    result = loader._parse_type(None)  # type: ignore[arg-type]
    assert isinstance(result, AnyType)


def test_parse_type_with_list_returns_any_type() -> None:
    """A list value is also not str or dict — must fall through to AnyType."""
    loader = ModuleLoader()
    result = loader._parse_type(["int", "string"])  # type: ignore[arg-type]
    assert isinstance(result, AnyType)


# ---------------------------------------------------------------------------
# Line 366  list_modules() public API
# ---------------------------------------------------------------------------


def test_list_modules_returns_sorted_names() -> None:
    """
    list_modules() must return the sorted names of all loaded modules.
    The result must be strictly sorted and match the keys of loader.modules.
    """
    loader = ModuleLoader()
    names = loader.list_modules()
    assert names == sorted(loader.modules.keys())
    assert names == sorted(names)


def test_list_modules_reflects_added_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    After loading a custom module via YARAAST_MODULE_SPEC_PATH_EXCLUSIVE,
    list_modules() must return exactly those module names, sorted.
    """
    spec_file = tmp_path / "xmod.json"
    spec_file.write_text(
        json.dumps(
            [
                {"name": "zebra_mod", "attributes": {"enabled": "bool"}},
                {"name": "apple_mod", "constants": {"K": "int"}},
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("YARAAST_MODULE_SPEC_PATH_EXCLUSIVE", str(spec_file))
    loader = ModuleLoader()

    assert loader.list_modules() == ["apple_mod", "zebra_mod"]


# ---------------------------------------------------------------------------
# Integration: combined path exercising several branches in _load_module_file
# ---------------------------------------------------------------------------


def test_load_module_file_dict_root_registers_module(tmp_path: Path) -> None:
    """
    A JSON file with a dict root (single module) must register the module by
    its 'name' key, not the stem of the file.  This confirms the dict branch
    of _load_module_file (lines 187-190) integrates correctly with _parse_module.
    """
    spec_file = tmp_path / "file_stem_irrelevant.json"
    spec_file.write_text(
        json.dumps({"name": "actual_name", "attributes": {"x": "int"}}),
        encoding="utf-8",
    )
    loader = ModuleLoader()
    loader._load_module_file(spec_file)
    assert "actual_name" in loader.modules


def test_load_module_file_list_root_registers_all_modules(tmp_path: Path) -> None:
    """
    A JSON file with a list root must register every object it contains.
    This verifies the list branch of _load_module_file (lines 191-198) in
    full through _parse_module.
    """
    spec_file = tmp_path / "multi.json"
    modules: list[dict[str, Any]] = [
        {"name": "alpha", "attributes": {"n": "int"}},
        {"name": "beta", "constants": {"C": "string"}},
    ]
    spec_file.write_text(json.dumps(modules), encoding="utf-8")
    loader = ModuleLoader()
    loader._load_module_file(spec_file)
    assert "alpha" in loader.modules
    assert "beta" in loader.modules
