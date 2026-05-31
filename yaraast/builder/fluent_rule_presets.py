"""Preset factories for common fluent rule patterns."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
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


def document_rule(name: str) -> FluentRuleBuilder:
    """Create a document-based rule template."""
    return FluentRuleBuilder(name).tagged("document").authored_by(FluentRuleBuilder.YARA_AST_STR)


def network_rule(name: str) -> FluentRuleBuilder:
    """Create a network-based detection rule."""
    return (
        FluentRuleBuilder(name)
        .tagged("network")
        .authored_by(FluentRuleBuilder.YARA_AST_STR)
        .ip_pattern()
        .url_pattern()
        .matches_any_of("$ip", "$url")
    )


def example_rules() -> YaraFile:
    """Create example rules using the fluent API."""
    from yaraast.builder.fluent_file_builder import yara_file

    return (
        yara_file()
        .import_module("pe")
        .import_module("math")
        .rule("example_malware")
        .tagged("malware", "example")
        .authored_by("Fluent API Demo")
        .described_as("Example malware detection rule")
        .string("$mz")
        .hex("4D 5A")
        .then()
        .string("$pe")
        .hex("50 45 00 00")
        .then()
        .string("$suspicious")
        .text("backdoor")
        .nocase()
        .then()
        .when(
            FluentConditionBuilder()
            .string_matches("$mz")
            .at(0)
            .and_(FluentConditionBuilder().string_matches("$pe"))
            .and_(FluentConditionBuilder().string_matches("$suspicious")),
        )
        .then_rule("example_packed")
        .tagged("packed")
        .authored_by("Fluent API Demo")
        .mz_header()
        .with_condition_builder(
            lambda c: c.string_matches("$mz").at(0).and_(c.high_entropy()).and_(c.pe_is_exe()),
        )
        .then_build_file()
    )
