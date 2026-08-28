"""Project configuration and policy-as-code for repository checks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
import tomllib
from typing import Any

from yaraast.diagnostics import Severity

_CONFIG_FILE = "yaraast.toml"
_DIALECTS = frozenset({"yara", "yara-x", "yara-l"})


@dataclass(frozen=True)
class MetadataPolicy:
    """Metadata requirements for checked rules."""

    required: tuple[str, ...] = ()
    allowed_status: tuple[str, ...] = ()


@dataclass(frozen=True)
class RulePolicy:
    """Static policy limits for rulesets."""

    max_rule_bytes: int | None = None
    max_strings_per_rule: int | None = None
    max_regex_length: int | None = None
    max_hex_wildcard_ratio: float | None = None
    forbid_unused_strings: bool = False
    forbid_duplicate_rule_names: bool = False
    require_tests_for_production: bool = False


@dataclass(frozen=True)
class QualityGate:
    """Thresholds used to determine whether a check passes."""

    max_errors: int = 0
    max_warnings: int | None = None
    fail_on: Severity = Severity.ERROR


@dataclass(frozen=True)
class ProjectConfig:
    """Validated project configuration for local and CI checks."""

    root: Path
    schema_version: int = 1
    dialect: str = "yara"
    include: tuple[str, ...] = ("**/*.yar", "**/*.yara")
    exclude: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    metadata: MetadataPolicy = field(default_factory=MetadataPolicy)
    policy: RulePolicy = field(default_factory=RulePolicy)
    severity: Mapping[str, Severity] = field(default_factory=dict)
    quality_gate: QualityGate = field(default_factory=QualityGate)
    profile: str = "default"

    @classmethod
    def load(cls, path: str | Path = ".", profile: str = "default") -> ProjectConfig:
        """Load a project config from a directory, file, or pyproject.toml."""
        source = Path(path)
        if source.is_dir():
            source, data = _find_config(source)
        else:
            data = _read_toml(source)
            if source.name == "pyproject.toml":
                data = data.get("tool", {}).get("yaraast", {})
        if not isinstance(data, Mapping):
            raise ValueError("YaraAST configuration must be a TOML table")
        selected = _select_profile(data, profile)
        return cls._from_mapping(source.parent, selected, profile)

    @classmethod
    def _from_mapping(
        cls,
        root: Path,
        data: Mapping[str, Any],
        profile: str,
    ) -> ProjectConfig:
        schema_version = _int_value(data.get("schema-version", 1), "schema-version")
        if schema_version != 1:
            raise ValueError(f"unsupported YaraAST config schema-version: {schema_version}")
        dialect = _string_value(data.get("dialect", "yara"), "dialect")
        if dialect not in _DIALECTS:
            raise ValueError(f"dialect must be one of: {', '.join(sorted(_DIALECTS))}")

        metadata = _table(data.get("metadata", {}), "metadata")
        policy = _table(data.get("policy", {}), "policy")
        severity_data = _table(data.get("severity", {}), "severity")
        gate = _table(data.get("quality-gate", {}), "quality-gate")
        severity = {
            _string_value(key, "diagnostic id"): _severity_value(value, key)
            for key, value in severity_data.items()
        }
        return cls(
            root=root,
            schema_version=schema_version,
            dialect=dialect,
            include=_string_tuple(data.get("include", ("**/*.yar", "**/*.yara")), "include"),
            exclude=_string_tuple(data.get("exclude", ()), "exclude"),
            targets=_string_tuple(data.get("targets", ()), "targets"),
            metadata=MetadataPolicy(
                required=_string_tuple(metadata.get("required", ()), "metadata.required"),
                allowed_status=_string_tuple(
                    metadata.get("allowed-status", ()), "metadata.allowed-status"
                ),
            ),
            policy=RulePolicy(
                max_rule_bytes=_optional_int(policy.get("max-rule-bytes"), "max-rule-bytes"),
                max_strings_per_rule=_optional_int(
                    policy.get("max-strings-per-rule"), "max-strings-per-rule"
                ),
                max_regex_length=_optional_int(
                    policy.get("max-regex-length"), "max-regex-length"
                ),
                max_hex_wildcard_ratio=_optional_float(
                    policy.get("max-hex-wildcard-ratio"), "max-hex-wildcard-ratio"
                ),
                forbid_unused_strings=_bool_value(
                    policy.get("forbid-unused-strings", False), "forbid-unused-strings"
                ),
                forbid_duplicate_rule_names=_bool_value(
                    policy.get("forbid-duplicate-rule-names", False),
                    "forbid-duplicate-rule-names",
                ),
                require_tests_for_production=_bool_value(
                    policy.get("require-tests-for-production", False),
                    "require-tests-for-production",
                ),
            ),
            severity=severity,
            quality_gate=QualityGate(
                max_errors=_int_value(gate.get("max-errors", 0), "quality-gate.max-errors"),
                max_warnings=_optional_int(gate.get("max-warnings"), "quality-gate.max-warnings"),
                fail_on=_severity_value(gate.get("fail-on", "error"), "quality-gate.fail-on"),
            ),
            profile=profile,
        )


def _find_config(root: Path) -> tuple[Path, Mapping[str, Any]]:
    config_path = root / _CONFIG_FILE
    if config_path.is_file():
        return config_path, _read_toml(config_path)
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = _read_toml(pyproject).get("tool", {}).get("yaraast", {})
        return pyproject, data
    return root / _CONFIG_FILE, {}


def _read_toml(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except FileNotFoundError:
        raise ValueError(f"configuration file not found: {path}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid TOML in {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"configuration file must contain a TOML table: {path}")
    return value


def _select_profile(data: Mapping[str, Any], profile: str) -> Mapping[str, Any]:
    profiles = data.get("profile", {})
    if not isinstance(profiles, Mapping):
        raise ValueError("profile must be a TOML table")
    if profile == "default":
        base: dict[str, Any] = {key: value for key, value in data.items() if key != "profile"}
    else:
        base = {key: value for key, value in data.items() if key != "profile"}
        base.update(_profile_mapping(profiles, profile, set()))
        if "fail-on" in base:
            gate = dict(_table(base.get("quality-gate", {}), "quality-gate"))
            gate["fail-on"] = base.pop("fail-on")
            base["quality-gate"] = gate
    return base


def _profile_mapping(
    profiles: Mapping[str, Any],
    name: str,
    active: set[str],
) -> Mapping[str, Any]:
    if name == "default":
        return {}
    if name in active:
        raise ValueError(f"profile inheritance cycle at {name!r}")
    raw = profiles.get(name)
    if not isinstance(raw, Mapping):
        raise ValueError(f"profile not found: {name}")
    active.add(name)
    parent_name = raw.get("extends")
    merged: dict[str, Any] = {}
    if parent_name is not None:
        parent = _string_value(parent_name, f"profile {name}.extends")
        merged.update(_profile_mapping(profiles, parent, active))
    merged.update({key: value for key, value in raw.items() if key != "extends"})
    active.remove(name)
    return merged


def _table(value: object, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a TOML table")
    return value


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list | tuple):
        raise ValueError(f"{field_name} must be an array of strings")
    return tuple(_string_value(item, field_name) for item in value)


def _string_value(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _int_value(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _optional_int(value: object, field_name: str) -> int | None:
    return None if value is None else _int_value(value, field_name)


def _optional_float(value: object, field_name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
        raise ValueError(f"{field_name} must be a number between 0 and 1")
    return float(value)


def _bool_value(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _severity_value(value: object, field_name: str) -> Severity:
    if not isinstance(value, str):
        choices = ", ".join(item.value for item in Severity)
        raise ValueError(f"{field_name} must be one of: {choices}")
    try:
        return Severity(value)
    except (TypeError, ValueError) as exc:
        choices = ", ".join(item.value for item in Severity)
        raise ValueError(f"{field_name} must be one of: {choices}") from exc
