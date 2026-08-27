"""Validate the repository-owned OSS-Fuzz submission candidate."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "oss-fuzz" / "project.yaml"
DOCKERFILE = ROOT / "oss-fuzz" / "Dockerfile"
BUILD = ROOT / "oss-fuzz" / "build.sh"


def main() -> None:
    project = PROJECT.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    build = BUILD.read_text(encoding="utf-8")

    required_project_values = (
        "language: python3",
        "fuzzing_engines:\n  - libfuzzer",
        "sanitizers:\n  - address\n  - undefined",
    )
    for value in required_project_values:
        if value not in project:
            raise SystemExit(f"project.yaml missing {value!r}")
    if "base-builder-python" not in dockerfile:
        raise SystemExit("Dockerfile must use the OSS-Fuzz Python base image")
    if "for target in parser roundtrip" not in build:
        raise SystemExit("build.sh must build both fuzz targets")
    for target in ("parser", "roundtrip"):
        if "yaraast_${target}_fuzzer" not in build:
            raise SystemExit(f"build.sh missing {target} target")


if __name__ == "__main__":
    main()
