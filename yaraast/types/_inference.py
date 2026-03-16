"""Compatibility reexports for type inference."""

from __future__ import annotations

from ._expr_inference import ExpressionTypeInference as TypeInference
from ._ruleset_inference import RulesetTypeInference

__all__ = ["RulesetTypeInference", "TypeInference"]
