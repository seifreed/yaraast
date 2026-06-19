"""Preset factories for common fluent rule patterns."""

from __future__ import annotations

from yaraast.builder.fluent_rule_builder import FluentRuleBuilder


def rule(name: str) -> FluentRuleBuilder:
    """Create a new fluent rule builder."""
    return FluentRuleBuilder(name)


def malware_rule(name: str) -> FluentRuleBuilder:
    """Create a malware detection rule template."""
    return (
        FluentRuleBuilder(name)
        .tagged("malware")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .mz_header()
        .for_pe_files()
    )


def trojan_rule(name: str) -> FluentRuleBuilder:
    """Create a trojan detection rule template."""
    return (
        FluentRuleBuilder(name)
        .tagged("trojan", "malware")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .mz_header()
        .for_pe_files()
    )


def packed_rule(name: str) -> FluentRuleBuilder:
    """Create a packed executable rule template."""
    return (
        FluentRuleBuilder(name)
        .tagged("packed")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .mz_header()
        .with_condition_builder(
            lambda c: c.string_matches("$mz").at(0).and_(c.high_entropy()),
        )
    )
