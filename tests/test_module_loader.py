"""Test module loader functionality."""

import json
import os
import tempfile
from pathlib import Path

from yaraast.types.module_loader import ModuleLoader
from yaraast.types.type_system import ArrayType, IntegerType


def test_builtin_modules() -> None:
    """Test loading of builtin modules."""
    loader = ModuleLoader()

    # Should have builtin modules
    assert "pe" in loader.modules
    assert "elf" in loader.modules
    assert "math" in loader.modules

    # Check PE module
    pe_module = loader.get_module("pe")
    assert pe_module is not None
    assert "machine" in pe_module.attributes
    assert "imphash" in pe_module.functions


def test_load_json_module() -> None:
    """Test loading module from JSON file."""
    # Create temporary JSON module
    module_json = {
        "name": "test_module",
        "attributes": {"version": "int", "data": "string[]"},
        "functions": {
            "process": {
                "return": "bool",
                "parameters": [{"name": "input", "type": "string"}],
            },
        },
        "constants": {"MAX_SIZE": "int"},
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "test_module.json"
        with json_path.open("w") as f:
            json.dump(module_json, f)

        # Set environment variable
        os.environ["YARAAST_MODULE_SPEC_PATH"] = tmpdir

        # Load modules
        loader = ModuleLoader()

        # Check module was loaded
        assert "test_module" in loader.modules
        module = loader.get_module("test_module")
        assert module is not None

        # Check attributes
        assert "version" in module.attributes
        assert isinstance(module.attributes["version"], IntegerType)
        assert "data" in module.attributes
        assert isinstance(module.attributes["data"], ArrayType)

        # Check functions
        assert "process" in module.functions
        func = module.functions["process"]
        assert func.name == "process"
        assert len(func.parameters) == 1
        assert func.parameters[0][0] == "input"

        # Check constants
        assert "MAX_SIZE" in module.constants

        # Clean up
        del os.environ["YARAAST_MODULE_SPEC_PATH"]


def test_exclusive_module_path() -> None:
    """Test exclusive module loading (ignoring builtins)."""
    module_json = [{"name": "custom_only", "attributes": {"test": "string"}}]

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "modules.json"
        with json_path.open("w") as f:
            json.dump(module_json, f)

        # Set exclusive path
        os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"] = str(json_path)

        # Load modules
        loader = ModuleLoader()

        # Should only have our custom module
        assert "custom_only" in loader.modules
        assert "pe" not in loader.modules  # Builtin should be excluded
        assert len(loader.modules) == 1

        # Clean up
        del os.environ["YARAAST_MODULE_SPEC_PATH_EXCLUSIVE"]


def test_complex_types() -> None:
    """Test loading complex types from JSON."""
    module_json = {
        "name": "complex",
        "attributes": {
            "simple_array": "int[]",
            "nested": {
                "type": "struct",
                "fields": {"name": "string", "values": "int[]", "enabled": "bool"},
            },
            "dictionary": {"type": "dict", "key": "string", "value": "int"},
        },
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "complex.json"
        with json_path.open("w") as f:
            json.dump(module_json, f)

        os.environ["YARAAST_MODULE_SPEC_PATH"] = tmpdir

        loader = ModuleLoader()
        module = loader.get_module("complex")

        assert module is not None
        assert "simple_array" in module.attributes
        assert "nested" in module.attributes
        assert "dictionary" in module.attributes

        # Clean up
        del os.environ["YARAAST_MODULE_SPEC_PATH"]


def test_example_custom_module() -> None:
    """Test loading the example custom module."""
    # Load from default modules directory
    loader = ModuleLoader()

    # The example_custom.json should be loaded if it exists
    modules_dir = Path(__file__).parent.parent / "yaraast" / "types" / "modules"
    if modules_dir.exists() and (modules_dir / "example_custom.json").exists():
        assert "custom" in loader.modules

        custom = loader.get_module("custom")
        assert custom is not None
        assert "api_version" in custom.attributes
        assert "hash" in custom.functions
        assert "MAX_BUFFER_SIZE" in custom.constants


if __name__ == "__main__":
    test_builtin_modules()
    test_load_json_module()
    test_exclusive_module_path()
    test_complex_types()
    test_example_custom_module()
    print("✓ All module loader tests passed")
