"""Builder pattern for constructing YARA rules programmatically."""

from yaraast.builder.ast_transformer import (
    CloneTransformer,
    RuleTransformer,
    YaraFileTransformer,
    clone_rule,
    clone_yara_file,
    transform_rule,
    transform_yara_file,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.expression_builder import ExpressionBuilder
from yaraast.builder.file_builder import YaraFileBuilder
from yaraast.builder.fluent_condition_builder import (
    FluentConditionBuilder,
    all_of,
    all_of_them,
    any_of,
    any_of_them,
    condition,
    filesize_gt,
    large_file,
    match,
    not_them,
    one_of,
    small_file,
)
from yaraast.builder.fluent_file_builder import FluentYaraFileBuilder, yara_file
from yaraast.builder.fluent_rule_builder import FluentRuleBuilder
from yaraast.builder.fluent_rule_presets import (
    document_rule,
    example_rules,
    malware_rule,
    network_rule,
    packed_rule,
    rule,
    trojan_rule,
)

# Convenience functions
# Enhanced fluent builders
from yaraast.builder.fluent_string_builder import (
    FluentStringBuilder,
    hex_pattern,
    regex,
    string,
    text,
)
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.builder.rule_builder import RuleBuilder

__all__ = [
    "ConditionBuilder",
    "ExpressionBuilder",
    "FluentConditionBuilder",
    "FluentRuleBuilder",
    "FluentStringBuilder",
    "FluentYaraFileBuilder",
    "HexStringBuilder",
    "RuleBuilder",
    "YaraFileBuilder",
    "all_of",
    "all_of_them",
    "any_of",
    "any_of_them",
    "clone_rule",
    "clone_yara_file",
    "condition",
    "document_rule",
    "example_rules",
    "filesize_gt",
    "hex_pattern",
    "large_file",
    "malware_rule",
    "match",
    "network_rule",
    "not_them",
    "one_of",
    "packed_rule",
    "regex",
    "rule",
    "small_file",
    # Convenience functions
    "string",
    "text",
    "transform_rule",
    "transform_yara_file",
    "trojan_rule",
    "yara_file",
]
