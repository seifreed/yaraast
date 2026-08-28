"""Built-in compatibility profiles for local rule checks."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TargetProfile:
    """Capabilities and optional local engine for one deployment target."""

    name: str
    dialect: str
    engine_version: str | None
    allowed_modules: frozenset[str]
    supports_includes: bool
    supports_externals: bool
    maximum_ruleset_bytes: int | None
    forbidden_constructs: frozenset[str]


_YARA_MODULES = frozenset({"cuckoo", "dotnet", "elf", "hash", "math", "pe", "time", "vt"})

TARGET_PROFILES: dict[str, TargetProfile] = {
    "yara-4.5.8": TargetProfile(
        "yara-4.5.8", "yara", "4.5.8", _YARA_MODULES, True, True, None, frozenset()
    ),
    "yara-x-1.20.0": TargetProfile(
        "yara-x-1.20.0", "yara-x", "1.20.0", _YARA_MODULES, True, True, None, frozenset()
    ),
    "virustotal-livehunt": TargetProfile(
        "virustotal-livehunt",
        "yara",
        None,
        frozenset({"vt"}),
        False,
        False,
        1_000_000,
        frozenset(),
    ),
    "google-secops-yaral": TargetProfile(
        "google-secops-yaral", "yara-l", None, frozenset(), False, False, None, frozenset()
    ),
}


def get_target_profile(name: str) -> TargetProfile:
    """Return a built-in target profile by name."""
    try:
        return TARGET_PROFILES[name]
    except KeyError as exc:
        choices = ", ".join(sorted(TARGET_PROFILES))
        raise ValueError(f"unknown target {name!r}; choose one of: {choices}") from exc
