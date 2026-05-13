"""Compatibility checks for ASTs passed to libyara-backed services."""

from __future__ import annotations

from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures


def libyara_incompatible_features(ast: object) -> list[str]:
    """Return YARA-X-only features that libyara cannot compile."""
    if not hasattr(ast, "accept") or not hasattr(ast, "rules"):
        return []

    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    blocking = [
        issue
        for issue in checker.check(ast)
        if issue.issue_type == "yarax_feature" and issue.severity == "error"
    ]
    return sorted(
        {
            issue.message.split(": ", 1)[1] if ": " in issue.message else issue.message
            for issue in blocking
        }
    )


def libyara_compatibility_error(ast: object, prefix: str) -> str | None:
    """Build a libyara compatibility error message, if one is needed."""
    features = libyara_incompatible_features(ast)
    if not features:
        return None
    return prefix + ": " + ", ".join(features)


def ensure_libyara_compatible_ast(ast: object, *, action: str = "use") -> None:
    """Raise when an AST contains syntax libyara cannot compile."""
    message = libyara_compatibility_error(
        ast,
        f"Cannot {action} YARA-X-only syntax with libyara",
    )
    if message:
        raise ValueError(message)
