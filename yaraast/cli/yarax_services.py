"""YARA-X services for CLI (logic without IO)."""

from __future__ import annotations

import re

from yaraast.ast.base import require_string
from yaraast.cli.utils import parse_yara_file
from yaraast.codegen.generator import CodeGenerator
from yaraast.dialects import _strip_string_literals
from yaraast.errors import YaraASTError
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.generator import YaraXGenerator
from yaraast.yarax.parser import YaraXParser

LIST_LITERAL_PATTERN = (
    r"(?:^|\bcondition\s*:|\b(?:and|or|not)\s+|[=(:,]\s*)"
    r"\[[^\]\n]*(?:,|\.{3}|\b(?:true|false|lambda|match)\b|\"\")[^\]\n]*\]"
)
DICT_LITERAL_PATTERN = (
    r"(?:^|\bcondition\s*:|\b(?:and|or|not)\s+|[=(:,]\s*)" r"\{\s*(?:\"\"|\d+|true|false)\s*:"
)
SLICE_PATTERN = r"(?:[A-Za-z_$]\w*(?:\s*\([^)]*\))?|\"\"|\])\s*\[[^\]\n]*:[^\]\n]*\]"
TUPLE_INDEXING_PATTERN = r"\([^()\n]*,[^()\n]*\)\s*\["


def parse_yarax_content(content: str):
    content = require_string(content, "content")
    parser = YaraXParser(content)
    ast = parser.parse()
    generator = YaraXGenerator()
    return ast, generator.generate(ast)


def parse_yara_file_ast(file_path: str):
    return parse_yara_file(file_path)


def check_yarax_compatibility(ast, strict: bool):
    if not isinstance(strict, bool):
        msg = "strict must be a boolean"
        raise TypeError(msg)
    features = YaraXFeatures.yarax_strict() if strict else YaraXFeatures.yarax_compatible()
    checker = YaraXCompatibilityChecker(features)
    return checker.check(ast)


def convert_yara_to_yarax(content: str) -> str:
    content = require_string(content, "content")
    ast = parse_yara_source(content)
    generator = YaraXGenerator()
    return generator.generate(ast)


def convert_yarax_to_yara(content: str) -> str:
    content = require_string(content, "content")
    parser = YaraXParser(content)
    ast = parser.parse()
    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    blocking_features = [
        issue
        for issue in checker.check(ast)
        if issue.issue_type == "yarax_feature" and issue.severity == "error"
    ]
    if blocking_features:
        features = sorted(
            {
                issue.message.split(": ", 1)[1] if ": " in issue.message else issue.message
                for issue in blocking_features
            }
        )
        msg = "Cannot convert YARA-X-only syntax to standard YARA: " + ", ".join(features)
        raise ValueError(msg)
    generator = CodeGenerator()
    return generator.generate(ast)


def _features_from_parsed_ast(content: str) -> list[str]:
    try:
        ast = YaraXParser(content).parse()
    except YaraASTError:
        return []

    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    checker.check(ast)
    return sorted(checker.get_report()["yarax_features_used"])


def _add_feature(features: list[str], feature: str) -> None:
    if feature not in features:
        features.append(feature)


def detect_yarax_features(content: str) -> list[str]:
    content = require_string(content, "content")
    parsed_features = _features_from_parsed_ast(content)
    if parsed_features:
        return parsed_features

    scan_content = _strip_string_literals(content)
    features = []

    if re.search(r"\bwith\s+\$?\w+\s*=", scan_content, re.IGNORECASE):
        _add_feature(features, "with statements")
    if re.search(r"\[[^\]]+\bfor\s+\w+\s+in\s+[^\]]+\]", scan_content, re.IGNORECASE):
        _add_feature(features, "array comprehensions")
    if re.search(
        r"\{[^{}:]+:[^{}]+\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+[^{}]+\}",
        scan_content,
        re.IGNORECASE,
    ):
        _add_feature(features, "dict comprehensions")
    if re.search(LIST_LITERAL_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "list expressions")
    if re.search(DICT_LITERAL_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "dict expressions")
    if re.search(SLICE_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "slice expressions")
    if re.search(TUPLE_INDEXING_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "tuple indexing")
    if re.search(r"\blambda(?:\s+\w+(?:\s*,\s*\w+)*)?\s*:", scan_content, re.IGNORECASE):
        _add_feature(features, "lambda expressions")
    if re.search(r"\bmatch\s+[^{}]+\{[^{}]*=>", scan_content, re.IGNORECASE | re.DOTALL):
        _add_feature(features, "pattern matching")
    if re.search(r"(?<!\.)\.\.\.(?!\.)|\*\*", scan_content):
        _add_feature(features, "spread operators")

    return features


def get_default_playground_code() -> str:
    return """
rule yarax_demo {
    meta:
        description = "YARA-X feature demonstration"

    strings:
        $str1 = "test"
        $str2 = /pattern/i

    condition:
        with count = #str1, threshold = 5, xs = [s for s in ($str1, $str2) if s]:
            count > threshold and match count { 0 => false, _ => true }
}
""".lstrip()


def detect_playground_features(content: str) -> list[str]:
    content = require_string(content, "content")
    parsed_features = _features_from_parsed_ast(content)
    if parsed_features:
        return parsed_features

    scan_content = _strip_string_literals(content)
    features = []
    if re.search(r"\bwith\s+\$?\w+\s*=", scan_content, re.IGNORECASE):
        _add_feature(features, "with statements")
    if re.search(r"\[[^\]]+\bfor\s+\w+\s+in\s+[^\]]+\]", scan_content, re.IGNORECASE):
        _add_feature(features, "comprehensions")
    if re.search(LIST_LITERAL_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "list expressions")
    if re.search(DICT_LITERAL_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "dict expressions")
    if re.search(SLICE_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "slice expressions")
    if re.search(TUPLE_INDEXING_PATTERN, scan_content, re.IGNORECASE):
        _add_feature(features, "tuple indexing")
    if re.search(r"\blambda(?:\s+\w+(?:\s*,\s*\w+)*)?\s*:", scan_content, re.IGNORECASE):
        _add_feature(features, "lambda expressions")
    return features
