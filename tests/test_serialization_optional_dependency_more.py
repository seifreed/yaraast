from __future__ import annotations

from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_import_probe(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_serialization_import_degrades_without_google_protobuf() -> None:
    result = _run_import_probe(
        """
import builtins

real_import = builtins.__import__

def import_without_protobuf(name, globals=None, locals=None, fromlist=(), level=0):
    if name.startswith("google.protobuf"):
        raise ModuleNotFoundError(
            "No module named 'google.protobuf'",
            name="google.protobuf",
        )
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = import_without_protobuf

from yaraast import serialization

assert serialization.ProtobufSerializer is None
assert serialization.JsonSerializer.__name__ == "JsonSerializer"
""",
    )

    assert result.returncode == 0, result.stderr


def test_serialization_import_propagates_internal_protobuf_errors() -> None:
    result = _run_import_probe(
        """
import builtins

real_import = builtins.__import__

def import_with_broken_protobuf_serializer(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "yaraast.serialization.protobuf_serializer":
        raise ImportError(
            "broken protobuf conversion",
            name="yaraast.serialization.protobuf_conversion",
        )
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = import_with_broken_protobuf_serializer

try:
    import yaraast.serialization
except ImportError as exc:
    assert exc.name == "yaraast.serialization.protobuf_conversion"
else:
    raise AssertionError("internal protobuf import errors must not be hidden")
""",
    )

    assert result.returncode == 0, result.stderr
