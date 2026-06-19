"""Regression tests for the builder package root surface."""

from __future__ import annotations

import yaraast.builder as builder


def test_builder_package_root_does_not_reexport_removed_helpers() -> None:
    removed_names = {
        "CloneTransformer",
        "RuleTransformer",
        "YaraFileTransformer",
        "clone_rule",
        "clone_yara_file",
        "transform_rule",
        "transform_yara_file",
        "ConditionBuilder",
        "ExpressionBuilder",
        "YaraFileBuilder",
        "FluentConditionBuilder",
        "FluentYaraFileBuilder",
        "FluentRuleBuilder",
        "FluentStringBuilder",
        "HexStringBuilder",
        "RuleBuilder",
        "yara_file",
    }

    for name in removed_names:
        assert not hasattr(builder, name), name
