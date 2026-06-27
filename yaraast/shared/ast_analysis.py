"""AST formatting and diff services shared by CLI and LSP."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
import hashlib
import json
from os import PathLike, fspath
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode, YaraFile, require_yara_file
from yaraast.ast.expressions import Expression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.codegen.pretty_printer import pretty_print
from yaraast.errors import YaraASTError
from yaraast.parser.source import parse_yara_source, parse_yara_source_with_comments
from yaraast.shared.path_safety import path_has_symlink_ancestor, path_is_symlink
from yaraast.visitor.base import BaseVisitor
from yaraast.yarax.generator import YaraXGenerator

type StringDef = PlainString | HexString | RegexString


def _path_access_error(path: Path) -> ValueError:
    msg = f"path could not be accessed: {path}"
    return ValueError(msg)


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_exists_and_is_dir(path: Path) -> bool:
    return _path_exists(path) and _path_is_dir(path)


def _require_file_path(value: object, name: str) -> Path:
    if isinstance(value, bool | bytes) or not isinstance(value, str | PathLike):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    raw_path = fspath(value)
    if not isinstance(raw_path, str):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    if "\x00" in raw_path:
        msg = f"{name} must not contain null bytes"
        raise ValueError(msg)
    path = Path(raw_path)
    if _path_exists_and_is_dir(path):
        msg = f"{name} must not be a directory"
        raise ValueError(msg)
    if path_is_symlink(path):
        msg = f"{name} must not traverse a symlink"
        raise ValueError(msg)
    return path


def _read_yara_text_file(path: Path) -> str:
    try:
        with path.open(encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


@dataclass
class ASTDiffResult:
    """Result of AST-based diff analysis."""

    has_changes: bool
    logical_changes: list[str] = field(default_factory=list)
    structural_changes: list[str] = field(default_factory=list)
    style_only_changes: list[str] = field(default_factory=list)
    added_rules: list[str] = field(default_factory=list)
    removed_rules: list[str] = field(default_factory=list)
    modified_rules: list[str] = field(default_factory=list)
    change_summary: dict[str, int] = field(default_factory=dict)


class ASTStructuralAnalyzer(BaseVisitor[Any]):
    """Analyze AST structure for diffing purposes."""

    def __init__(self) -> None:
        super().__init__()
        self.structural_hash: dict[str, str] = {}
        self.rule_signatures: dict[str, str] = {}
        self.string_signatures: dict[str, str] = {}
        self.condition_signatures: dict[str, str] = {}

    def analyze(self, ast: YaraFile) -> dict[str, Any]:
        self.structural_hash.clear()
        self.rule_signatures.clear()
        self.string_signatures.clear()
        self.condition_signatures.clear()
        self.visit(ast)
        return {
            "structural_hash": dict(self.structural_hash),
            "rule_signatures": dict(self.rule_signatures),
            "string_signatures": dict(self.string_signatures),
            "condition_signatures": dict(self.condition_signatures),
            "total_rules": len(ast.rules),
            "total_imports": len(ast.imports),
            "total_includes": len(ast.includes),
        }

    def visit_yara_file(self, node: YaraFile) -> Any:
        rule_counts = Counter(rule.name for rule in node.rules)
        seen_rules: defaultdict[str, int] = defaultdict(int)
        self.structural_hash["file"] = self._hash_dict(
            {
                "imports": [imp.module for imp in node.imports],
                "includes": [inc.path for inc in node.includes],
                "rules": [rule.name for rule in node.rules],
            }
        )
        for rule in node.rules:
            seen_rules[rule.name] += 1
            signature_key = self._occurrence_key(rule.name, seen_rules[rule.name], rule_counts)
            self._record_rule(rule, signature_key)
        return None

    def visit_rule(self, rule: Rule) -> Any:
        self._record_rule(rule, rule.name)
        return super().visit_rule(rule)

    def _record_rule(self, rule: Rule, signature_key: str) -> None:
        meta_data = getattr(rule, "meta", [])
        meta_keys = sorted([getattr(m, "key", "") for m in meta_data if hasattr(m, "key")])
        meta_entries = sorted(
            [
                {
                    "key": getattr(meta, "key", ""),
                    "value": self._condition_value_structure(getattr(meta, "value", "")),
                    "scope": getattr(getattr(meta, "scope", None), "value", ""),
                }
                for meta in meta_data
                if hasattr(meta, "key")
            ],
            key=lambda item: (str(item["key"]), str(item["value"]), str(item["scope"])),
        )

        self.rule_signatures[signature_key] = self._hash_dict(
            {
                "name": rule.name,
                "modifiers": sorted(str(m) for m in getattr(rule, "modifiers", [])),
                "tags": sorted([tag.name for tag in getattr(rule, "tags", [])]),
                "meta_keys": meta_keys,
                "meta_entries": meta_entries,
                "string_identifiers": sorted([s.identifier for s in getattr(rule, "strings", [])]),
                "has_condition": rule.condition is not None,
            }
        )

        strings = getattr(rule, "strings", [])
        string_counts = Counter(string_def.identifier for string_def in strings)
        seen_strings: defaultdict[str, int] = defaultdict(int)
        for string_def in strings:
            seen_strings[string_def.identifier] += 1
            string_key = self._occurrence_key(
                string_def.identifier,
                seen_strings[string_def.identifier],
                string_counts,
            )
            self._analyze_string(string_def, signature_key, string_key)
        if rule.condition is not None:
            self._analyze_condition(rule.condition, signature_key)

    def _occurrence_key(self, name: str, occurrence: int, counts: Counter[str]) -> str:
        if counts[name] == 1:
            return name
        return f"{name}#{occurrence}"

    def _analyze_string(
        self,
        string_def: StringDef,
        rule_name: str = "",
        string_key: str | None = None,
    ) -> None:
        string_structure = {
            "identifier": string_def.identifier,
            "type": type(string_def).__name__,
            "modifiers": sorted([str(mod) for mod in getattr(string_def, "modifiers", [])]),
        }
        if hasattr(string_def, "value"):
            string_structure["content_type"] = "literal"
            string_structure["content_hash"] = self._literal_content_hash(string_def.value)
        elif hasattr(string_def, "regex"):
            string_structure["content_type"] = "regex"
            string_structure["content_hash"] = hashlib.md5(
                str(string_def.regex).encode(),
                usedforsecurity=False,
            ).hexdigest()
        elif hasattr(string_def, "tokens"):
            string_structure["content_type"] = "hex"
            tokens = getattr(string_def, "tokens", [])
            string_structure["token_count"] = str(len(tokens))
            string_structure["tokens"] = self._condition_value_structure(tokens)
        identifier = string_key or string_def.identifier
        sig_key = f"{rule_name}:{identifier}" if rule_name else identifier
        self.string_signatures[sig_key] = self._hash_dict(string_structure)

    def _analyze_condition(self, condition: Expression, rule_name: str) -> None:
        self.condition_signatures[f"{rule_name}.condition"] = self._hash_dict(
            self._get_condition_structure(condition)
        )

    def _get_condition_structure(self, node: ASTNode | None) -> dict[str, Any]:
        if node is None:
            return {"type": "empty"}
        structure: dict[str, Any] = {"type": type(node).__name__}
        for field_info in fields(node):
            if field_info.name in ASTNode._METADATA_FIELDS:
                continue
            structure[field_info.name] = self._condition_value_structure(
                getattr(node, field_info.name)
            )
        structure["children"] = [self._get_condition_structure(child) for child in node.children()]
        return structure

    def _condition_value_structure(self, value: Any) -> Any:
        if isinstance(value, ASTNode):
            return self._get_condition_structure(value)
        if isinstance(value, Mapping):
            return {
                str(key): self._condition_value_structure(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        if isinstance(value, list | tuple):
            return [self._condition_value_structure(item) for item in value]
        if isinstance(value, set | frozenset):
            return sorted(
                [self._condition_value_structure(item) for item in value],
                key=str,
            )
        if isinstance(value, str | int | float | bool) or value is None:
            return value
        return str(value)

    def _literal_content_hash(self, value: str | bytes) -> str:
        hasher = hashlib.md5(usedforsecurity=False)
        if isinstance(value, bytes):
            hasher.update(b"bytes\0")
            hasher.update(value)
        else:
            hasher.update(b"str\0")
            hasher.update(value.encode())
        return hasher.hexdigest()

    def _hash_dict(self, data: dict[str, Any]) -> str:
        payload = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()


class ASTDiffer:
    """Compare ASTs and identify logical vs stylistic changes."""

    def diff_files(
        self,
        file1_path: str | PathLike[str],
        file2_path: str | PathLike[str],
    ) -> ASTDiffResult:
        try:
            file1 = _require_file_path(file1_path, "file1_path")
            file2 = _require_file_path(file2_path, "file2_path")
            content1 = _read_yara_text_file(file1)
            ast1 = parse_yara_source(content1)
            content2 = _read_yara_text_file(file2)
            ast2 = parse_yara_source(content2)
            result = self.diff_asts(ast1, ast2)
            return self._detect_style_changes_from_text(content1, content2, result)
        except (TypeError, ValueError, YaraASTError, OSError) as exc:
            result = ASTDiffResult(has_changes=True)
            result.logical_changes.append(f"Error comparing files: {exc}")
            return result

    def diff_asts(self, ast1: YaraFile, ast2: YaraFile) -> ASTDiffResult:
        analysis1 = ASTStructuralAnalyzer().analyze(ast1)
        analysis2 = ASTStructuralAnalyzer().analyze(ast2)
        result = ASTDiffResult(has_changes=False)

        if analysis1["structural_hash"]["file"] != analysis2["structural_hash"]["file"]:
            result.structural_changes.append("File structure changed (imports/includes/rule order)")
            result.has_changes = True

        rules1 = set(analysis1["rule_signatures"].keys())
        rules2 = set(analysis2["rule_signatures"].keys())
        result.added_rules = sorted(rules2 - rules1)
        result.removed_rules = sorted(rules1 - rules2)
        result.modified_rules = []

        for rule_name in sorted(rules1 & rules2):
            if analysis1["rule_signatures"][rule_name] != analysis2["rule_signatures"][rule_name]:
                result.modified_rules.append(rule_name)
                result.logical_changes.append(
                    f"Rule '{rule_name}' modified (logic/structure changed)"
                )

        strings1 = set(analysis1["string_signatures"].keys())
        strings2 = set(analysis2["string_signatures"].keys())
        added_strings = sorted(strings2 - strings1)
        removed_strings = sorted(strings1 - strings2)
        if added_strings:
            result.logical_changes.append(f"Added strings: {', '.join(added_strings)}")
        if removed_strings:
            result.logical_changes.append(f"Removed strings: {', '.join(removed_strings)}")

        for string_id in sorted(strings1 & strings2):
            if (
                analysis1["string_signatures"][string_id]
                != analysis2["string_signatures"][string_id]
            ):
                result.logical_changes.append(f"String '{string_id}' content modified")

        conditions1 = analysis1["condition_signatures"]
        conditions2 = analysis2["condition_signatures"]
        for condition_name in sorted(set(conditions1) & set(conditions2)):
            if conditions1[condition_name] != conditions2[condition_name]:
                rule_name = condition_name.removesuffix(".condition")
                result.logical_changes.append(f"Condition logic changed in rule '{rule_name}'")

        result.has_changes = bool(
            result.logical_changes
            or result.structural_changes
            or result.added_rules
            or result.removed_rules
        )
        result.change_summary = {
            "logical_changes": len(result.logical_changes),
            "structural_changes": len(result.structural_changes),
            "added_rules": len(result.added_rules),
            "removed_rules": len(result.removed_rules),
            "modified_rules": len(result.modified_rules),
            "style_only_changes": len(result.style_only_changes),
            "style_changes": len(result.style_only_changes),
        }
        return result

    def _detect_style_changes_from_text(
        self,
        content1: str,
        content2: str,
        result: ASTDiffResult,
    ) -> ASTDiffResult:
        result.change_summary.setdefault("style_changes", 0)
        result.change_summary.setdefault("style_only_changes", 0)
        if content1 != content2 and not (
            result.logical_changes
            or result.structural_changes
            or result.added_rules
            or result.removed_rules
        ):
            result.has_changes = True
            result.style_only_changes.append("spacing/formatting or whitespace/indentation changed")
            result.change_summary["style_only_changes"] = len(result.style_only_changes)
            result.change_summary["style_changes"] = len(result.style_only_changes)
        return result


class ASTFormatter:
    """AST-based code formatter using CodeGenerator."""

    _STYLES = frozenset({"compact", "default", "pretty", "verbose"})

    def __init__(self) -> None:
        self.generator = YaraXGenerator()

    def format_file(
        self,
        input_path: str | PathLike[str],
        output_path: str | PathLike[str] | None = None,
        style: object = "default",
    ) -> tuple[bool, str]:
        try:
            input_file = _require_file_path(input_path, "input_path")
            output_file = self._optional_output_path(output_path)
        except (TypeError, ValueError) as exc:
            return False, f"Formatting error: {exc}"

        try:
            content = _read_yara_text_file(input_file)
        except ValueError as exc:
            return False, f"Formatting error: {exc}"

        try:
            ast = parse_yara_source_with_comments(content)
            formatted = self.format_ast(ast, style)
            if output_file is not None:
                with output_file.open("w", encoding="utf-8") as f:
                    f.write(formatted)
                return True, f"Formatted file written to {output_file}"
            return True, formatted
        except (YaraASTError, OSError) as exc:
            return False, f"Formatting error: {exc}"

    def format_ast(self, ast: YaraFile, style: object = "default") -> str:
        ast = require_yara_file(ast, "ast")
        style = self._require_style(style)
        if style == "compact":
            return self.generator.generate(ast)
        return pretty_print(ast)

    def _require_style(self, style: object) -> str:
        if not isinstance(style, str):
            raise TypeError("format style must be a string")
        if style not in self._STYLES:
            valid = ", ".join(sorted(self._STYLES))
            raise ValueError(f"format style must be one of: {valid}")
        return style

    def _optional_output_path(self, output_path: object) -> Path | None:
        if output_path is None:
            return None
        if isinstance(output_path, bool) or not isinstance(output_path, str | PathLike):
            msg = "output_path must be a file path"
            raise TypeError(msg)
        raw_path = fspath(output_path)
        if not isinstance(raw_path, str):
            msg = "output_path must be a file path"
            raise TypeError(msg)
        if not raw_path.strip():
            msg = "output_path must not be empty"
            raise ValueError(msg)
        if "\x00" in raw_path:
            msg = "output_path must not contain null bytes"
            raise ValueError(msg)
        path = Path(raw_path)
        if _path_exists_and_is_dir(path):
            msg = "output_path must not be a directory"
            raise ValueError(msg)
        if path_is_symlink(path) or path_has_symlink_ancestor(path):
            msg = "output_path must not traverse a symlink"
            raise ValueError(msg)
        return path

    def check_format(self, file_path: str | PathLike[str]) -> tuple[bool, list[str]]:
        input_file = _require_file_path(file_path, "file_path")
        original = _read_yara_text_file(input_file)
        formatted = pretty_print(parse_yara_source_with_comments(original))
        if original.strip() == formatted.strip():
            return False, []
        issues = []
        for i, (orig, fmt) in enumerate(
            zip(original.strip().split("\n"), formatted.strip().split("\n"), strict=False),
            1,
        ):
            if orig != fmt:
                issues.append(f"Line {i}: formatting issue")
        return len(issues) > 0, issues
