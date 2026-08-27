"""Verify wheel and sdist behavior from isolated virtual environments."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv

REQUIRED_RESOURCES = (
    "py.typed",
    "types/modules/vt.json",
    "serialization/yara_ast.proto",
    "serialization/yara_ast_pb2.pyi",
)


def _venv_python(environment: Path) -> Path:
    if sys.platform == "win32":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _create_environment(environment: Path) -> None:
    uv = shutil.which("uv")
    if uv:
        subprocess.run([uv, "venv", "--python", sys.executable, str(environment)], check=True)
        return
    venv.create(environment, with_pip=True)


def _install(environment: Path, distribution: Path) -> None:
    python = _venv_python(environment)
    requirement = f"{distribution}[visualization]"
    uv = shutil.which("uv")
    if uv:
        subprocess.run([uv, "pip", "install", "--python", str(python), requirement], check=True)
        return
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            requirement,
        ],
        check=True,
    )


def _verify(environment: Path, expected_version: str, workdir: Path) -> None:
    python = _venv_python(environment)
    check = f"""
from importlib.metadata import version
from importlib.resources import files
import subprocess
import sys

assert version("yaraast") == {expected_version!r}
root = files("yaraast")
for relative in {REQUIRED_RESOURCES!r}:
    assert root.joinpath(relative).is_file(), relative
from yaraast.types.module_loader import ModuleLoader
assert ModuleLoader().get_module("vt") is not None
subprocess.run([sys.executable, "-m", "yaraast.cli.main", "--version"], check=True)
"""
    subprocess.run(
        [
            str(python),
            "-c",
            check,
        ],
        check=True,
        cwd=workdir,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("distribution_dir", type=Path)
    args = parser.parse_args()

    distributions = sorted(args.distribution_dir.glob("*.whl")) + sorted(
        args.distribution_dir.glob("*.tar.gz")
    )
    wheels = [path for path in distributions if path.suffix == ".whl"]
    sdists = [path for path in distributions if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("expected exactly one wheel and one sdist")

    expected_version = version_from_project()
    with tempfile.TemporaryDirectory(prefix="yaraast-package-smoke-") as temporary:
        root = Path(temporary)
        for label, distribution in (("wheel", wheels[0]), ("sdist", sdists[0])):
            environment = root / label
            _create_environment(environment)
            _install(environment, distribution.resolve())
            _verify(environment, expected_version, root)


def version_from_project() -> str:
    import tomllib

    with Path("pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


if __name__ == "__main__":
    main()
