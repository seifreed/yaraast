from __future__ import annotations

import builtins
from collections.abc import Callable
import importlib
import os
from pathlib import Path
import subprocess
import sys
import textwrap
from types import ModuleType
from typing import Any

import pytest

ImportFunction = Callable[[str, Any, Any, Any, int], ModuleType]


def test_libyara_modules_report_missing_backend_in_subprocess(tmp_path: Path) -> None:
    blocker = tmp_path / "yara.py"
    blocker.write_text('raise ImportError("blocked yara", name="yara")\n', encoding="utf-8")

    code = textwrap.dedent(
        """
        import os
        import sys

        sys.path.insert(0, os.getcwd())

        import yaraast.libyara as libyara
        from yaraast.libyara.compiler import LibyaraCompiler
        from yaraast.libyara.direct_compiler import DirectASTCompiler, OptimizedMatcher
        from yaraast.libyara.scanner import LibyaraScanner

        print(f"available={libyara.YARA_AVAILABLE}")

        try:
            libyara.EquivalenceTester
        except Exception as exc:
            print(f"attr={type(exc).__name__}:{exc}")

        for cls in [LibyaraCompiler, DirectASTCompiler, LibyaraScanner]:
            try:
                cls()
            except Exception as exc:
                print(f"{cls.__name__}={type(exc).__name__}:{exc}")

        try:
            OptimizedMatcher(object())
        except Exception as exc:
            print(f"OptimizedMatcher={type(exc).__name__}:{exc}")
        """,
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = (
        str(tmp_path) + os.pathsep + os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        env=env,
        capture_output=True,
        text=True,
        check=True,
        encoding="utf-8",
    )

    stdout = result.stdout
    assert "available=False" in stdout
    assert "attr=ImportError:'EquivalenceTester' requires yara-python." in stdout
    assert "LibyaraCompiler=ImportError:yara-python is not installed." in stdout
    assert "DirectASTCompiler=ImportError:yara-python is not installed." in stdout
    assert "LibyaraScanner=ImportError:yara-python is not installed." in stdout
    assert "OptimizedMatcher=ImportError:yara-python is not installed." in stdout


def test_libyara_modules_propagate_internal_backend_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yaraast.libyara as libyara_package
    import yaraast.libyara.compiler as compiler_module
    import yaraast.libyara.direct_compiler as direct_compiler_module
    import yaraast.libyara.scanner as scanner_module

    real_import: ImportFunction = builtins.__import__

    def fail_yara_internal_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yara":
            raise ImportError("broken yara binding", name="yara._native")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_yara_internal_import)
    try:
        for module in (
            libyara_package,
            compiler_module,
            direct_compiler_module,
            scanner_module,
        ):
            with pytest.raises(ImportError, match="broken yara binding"):
                importlib.reload(module)
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        importlib.reload(compiler_module)
        importlib.reload(direct_compiler_module)
        importlib.reload(scanner_module)
        importlib.reload(libyara_package)
