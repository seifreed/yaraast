"""Services for fluent CLI demos (logic without IO)."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from yaraast.builder import (
    malware_rule,
    packed_rule,
    rule,
    text,
    transform_rule,
    trojan_rule,
    yara_file,
)
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.codegen.generator import CodeGenerator


class RuleTemplate(StrEnum):
    """Supported rule template types."""

    MALWARE = "malware"
    TROJAN = "trojan"
    PACKED = "packed"
    DOCUMENT = "document"
    NETWORK = "network"


def generate_code(ast_or_rule) -> str:
    """Generate YARA code from AST or rule."""
    return CodeGenerator().generate(ast_or_rule)


def create_example_rules():
    """Create example rules using fluent API."""
    return (
        yara_file()
        .with_rule(
            rule("example_malware")
            .tagged("malware", "backdoor")
            .authored_by("Fluent API")
            .described_as("Example malware detection rule")
            .string("$mz")
            .hex("4D 5A")
            .then()
            .string("$suspicious")
            .text("backdoor")
            .nocase()
            .then()
            .condition("$mz at 0 and $suspicious")
            .build(),
        )
        .with_rule(
            rule("example_packer")
            .tagged("packer")
            .string("$upx")
            .text("UPX!")
            .then()
            .condition("$upx")
            .build(),
        )
        .build()
    )


def create_string_patterns_rule():
    """Create demo rule with string patterns."""
    return (
        rule("string_pattern_demo")
        .tagged("demo", "strings")
        .authored_by("Fluent API Demo")
        .described_as("Demonstration of string pattern builders")
        .string("$text1")
        .text("hello world")
        .nocase()
        .then()
        .string("$text2")
        .text("backdoor")
        .wide()
        .fullword()
        .then()
        .string("$text3")
        .text("password")
        .ascii()
        .private()
        .then()
        .string("$hex1")
        .hex("4D 5A ?? 00")
        .then()
        .string("$hex2")
        .hex("50 45 00 00")
        .then()
        .string("$hex3")
        .hex("?? FF FE ??")
        .then()
        .string("$regex1")
        .regex(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        .nocase()
        .then()
        .string("$regex2")
        .regex(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        .then()
        .mz_header("$mz")
        .pe_header("$pe")
        .email_pattern("$email")
        .ip_pattern("$ip")
        .url_pattern("$url")
        .string("$xor1")
        .text("malware")
        .xor(0x42)
        .then()
        .string("$xor2")
        .text("trojan")
        .xor()
        .then()
        .string("$b64")
        .text("payload")
        .base64()
        .then()
        .matches_any()
        .build()
    )


def create_condition_demo_rules():
    """Create demo rules for condition builders."""
    rules = []
    rules.append(
        rule("condition_demo")
        .tagged("demo", "conditions")
        .authored_by("Fluent API Demo")
        .described_as("Demonstration of condition builders")
        .text_string("$a", "malware")
        .text_string("$b", "trojan")
        .text_string("$c", "backdoor")
        .hex_string("$mz", "4D 5A")
        .hex_string("$pe", "50 45 00 00")
        .with_condition_builder(
            lambda c: (
                c.string_matches("$mz")
                .at(0)
                .and_(c.one_of("$a", "$b", "$c"))
                .and_(c.filesize_gt(1024))
                .and_(c.pe_is_exe())
            ),
        )
        .build(),
    )
    rules.append(
        rule("quantifier_demo")
        .tagged("demo")
        .text_string("$s1", "test1")
        .text_string("$s2", "test2")
        .text_string("$s3", "test3")
        .matches_any_of("$s1", "$s2", "$s3")
        .build(),
    )
    rules.append(
        rule("filesize_demo")
        .tagged("demo")
        .text_string("$test", "sample")
        .with_condition_builder(
            lambda c: c.string_matches("$test").and_(
                c.filesize_between(1024, 1024 * 1024),
            ),
        )
        .build(),
    )
    rules.append(
        rule("pe_demo")
        .tagged("demo", "pe")
        .mz_header()
        .with_condition_builder(
            lambda c: (
                c.string_matches("$mz").at(0).and_(c.pe_is_dll()).and_(c.pe_section_count_eq(3))
            ),
        )
        .build(),
    )
    return rules


def build_yara_file_with_rules(rules: Iterable) -> str:
    """Build a YARA file from rules and return generated code."""
    ast_builder = yara_file().import_module("pe").import_module("math")
    for r in rules:
        ast_builder.with_rule(r)
    return generate_code(ast_builder.build())


def create_transformation_rules():
    """Create demo rules for AST transformations."""
    base_rule = (
        malware_rule("base_malware")
        .described_as("Base malware detection rule")
        .text_string("$str1", "malware")
        .text_string("$str2", "backdoor")
        .matches_any()
        .build()
    )
    rules = [base_rule]
    rules.append(
        transform_rule(base_rule)
        .rename("variant_malware")
        .add_tag("variant")
        .set_author("Transformation Demo")
        .build(),
    )
    rules.append(
        transform_rule(base_rule)
        .add_prefix("win32_")
        .add_tag("windows")
        .prefix_strings("win_")
        .build(),
    )
    rules.append(
        transform_rule(base_rule).add_suffix("_private").make_private().add_tag("private").build(),
    )
    packed_base = packed_rule("packed_sample").described_as("Packed executable template").build()
    rules.append(packed_base)
    rules.append(
        transform_rule(packed_base)
        .rename("upx_packed")
        .add_tag("upx")
        .add_string(text("$upx", "UPX!").build())
        .transform_condition(
            lambda cond: (
                FluentConditionBuilder(cond)
                .and_(FluentConditionBuilder().string_matches("$upx"))
                .build()
            ),
        )
        .build(),
    )
    return rules


def _make_document_rule(rule_name: str):
    """Create a document detection template rule."""
    return (
        rule(rule_name)
        .tagged("document")
        .text_string("$doc1", "%PDF-")
        .text_string("$doc2", "PK\x03\x04")
        .text_string("$doc3", "\xd0\xcf\x11\xe0")
        .matches_any_of("$doc1", "$doc2", "$doc3")
    )


def _make_network_rule(rule_name: str):
    """Create a network detection template rule."""
    return (
        rule(rule_name).tagged("network").ip_pattern().url_pattern().email_pattern().matches_any()
    )


_TEMPLATE_FACTORIES = {
    RuleTemplate.MALWARE: lambda name: malware_rule(name),
    RuleTemplate.TROJAN: lambda name: trojan_rule(name),
    RuleTemplate.PACKED: lambda name: packed_rule(name),
    RuleTemplate.DOCUMENT: _make_document_rule,
    RuleTemplate.NETWORK: _make_network_rule,
}


def create_template_rule(rule_name: str, rule_type: str, author: str, tags: list[str]):
    """Create a template rule based on type.

    Accepts both RuleTemplate enum values and plain strings for backward
    compatibility.
    """
    factory = _TEMPLATE_FACTORIES.get(rule_type)  # type: ignore[arg-type]
    rule_ast = factory(rule_name) if factory is not None else rule(rule_name).tagged(rule_type)

    rule_ast = rule_ast.authored_by(author)
    for tag in tags:
        rule_ast = rule_ast.with_tag(tag)
    return rule_ast.build()
