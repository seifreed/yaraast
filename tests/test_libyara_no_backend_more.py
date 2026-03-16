from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


def test_libyara_modules_report_missing_backend_in_subprocess(tmp_path: Path) -> None:
    blocker = tmp_path / "yara.py"
    blocker.write_text('raise ImportError("blocked yara")\n', encoding="utf-8")

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
    )

    stdout = result.stdout
    assert "available=False" in stdout
    assert "attr=ImportError:'EquivalenceTester' requires yara-python." in stdout
    assert "LibyaraCompiler=ImportError:yara-python is not installed." in stdout
    assert "DirectASTCompiler=ImportError:yara-python is not installed." in stdout
    assert "LibyaraScanner=ImportError:yara-python is not installed." in stdout
    assert "OptimizedMatcher=ImportError:yara-python is not installed." in stdout
