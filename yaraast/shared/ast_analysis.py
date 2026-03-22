"""AST formatting and diff services shared by CLI and LSP."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.pretty_printer import PrettyPrinter
from yaraast.parser.parser import Parser
from yaraast.visitor.base import BaseVisitor


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
            "structural_hash": self.structural_hash,
            "rule_signatures": self.rule_signatures,
            "string_signatures": self.string_signatures,
            "condition_signatures": self.condition_signatures,
            "total_rules": len(ast.rules),
            "total_imports": len(ast.imports),
            "total_includes": len(ast.includes),
        }

    def visit_yara_file(self, node: YaraFile) -> Any:
        self.structural_hash["file"] = self._hash_dict(
            {
                "imports": [imp.module for imp in node.imports],
                "includes": [inc.path for inc in node.includes],
                "rules": [rule.name for rule in node.rules],
            }
        )
        for rule in node.rules:
            self.visit(rule)
        return super().visit_yara_file(node)

    def visit_rule(self, rule: Any) -> Any:
        meta_data = getattr(rule, "meta", [])
        if isinstance(meta_data, dict):
            meta_keys = sorted(meta_data.keys())
        else:
            meta_keys = sorted([m.key for m in meta_data if hasattr(m, "key")])

        self.rule_signatures[rule.name] = self._hash_dict(
            {
                "name": rule.name,
                "modifiers": sorted(getattr(rule, "modifiers", [])),
                "tags": sorted([tag.name for tag in getattr(rule, "tags", [])]),
                "meta_keys": meta_keys,
                "string_identifiers": sorted([s.identifier for s in getattr(rule, "strings", [])]),
                "has_condition": rule.condition is not None,
            }
        )

        for string_def in getattr(rule, "strings", []):
            self._analyze_string(string_def, rule.name)
        if rule.condition:
            self._analyze_condition(rule.condition, rule.name)
        return super().visit_rule(rule)

    def _analyze_string(self, string_def: Any, rule_name: str = "") -> None:
        string_structure = {
            "identifier": string_def.identifier,
            "type": type(string_def).__name__,
            "modifiers": sorted([str(mod) for mod in getattr(string_def, "modifiers", [])]),
        }
        if hasattr(string_def, "value"):
            string_structure["content_type"] = "literal"
            string_structure["content_hash"] = hashlib.md5(
                str(string_def.value).encode(),
                usedforsecurity=False,
            ).hexdigest()
        elif hasattr(string_def, "regex"):
            string_structure["content_type"] = "regex"
            string_structure["content_hash"] = hashlib.md5(
                str(string_def.regex).encode(),
                usedforsecurity=False,
            ).hexdigest()
        elif hasattr(string_def, "tokens"):
            string_structure["content_type"] = "hex"
            string_structure["token_count"] = len(getattr(string_def, "tokens", []))
        sig_key = f"{rule_name}:{string_def.identifier}" if rule_name else string_def.identifier
        self.string_signatures[sig_key] = self._hash_dict(string_structure)

    def _analyze_condition(self, condition: Any, rule_name: str) -> None:
        self.condition_signatures[f"{rule_name}.condition"] = self._hash_dict(
            self._get_condition_structure(condition)
        )

    def _get_condition_structure(self, node: Any) -> dict[str, Any]:
        if node is None:
            return {"type": "empty"}
        structure: dict[str, Any] = {"type": type(node).__name__}
        if hasattr(node, "operator"):
            structure["operator"] = node.operator
        if hasattr(node, "left") and hasattr(node, "right"):
            structure["left"] = self._get_condition_structure(node.left)
            structure["right"] = self._get_condition_structure(node.right)
        elif hasattr(node, "operand"):
            structure["operand"] = self._get_condition_structure(node.operand)
        elif hasattr(node, "children"):
            structure["children"] = [
                self._get_condition_structure(child) for child in node.children()
            ]
        return structure

    def _hash_dict(self, data: dict[str, Any]) -> str:
        payload = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()


class ASTDiffer:
    """Compare ASTs and identify logical vs stylistic changes."""

    def diff_files(self, file1_path: Path, file2_path: Path) -> ASTDiffResult:
        try:
            with Path(file1_path).open() as f:
                content1 = f.read()
                ast1 = Parser(content1).parse()
            with Path(file2_path).open() as f:
                content2 = f.read()
                ast2 = Parser(content2).parse()
            result = self.diff_asts(ast1, ast2)
            return self._detect_style_changes_from_text(content1, content2, result)
        except Exception as exc:
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
        result.added_rules = list(rules2 - rules1)
        result.removed_rules = list(rules1 - rules2)
        result.modified_rules = []

        for rule_name in rules1 & rules2:
            if analysis1["rule_signatures"][rule_name] != analysis2["rule_signatures"][rule_name]:
                result.modified_rules.append(rule_name)
                result.logical_changes.append(
                    f"Rule '{rule_name}' modified (logic/structure changed)"
                )

        strings1 = set(analysis1["string_signatures"].keys())
        strings2 = set(analysis2["string_signatures"].keys())
        added_strings = strings2 - strings1
        removed_strings = strings1 - strings2
        if added_strings:
            result.logical_changes.append(f"Added strings: {', '.join(added_strings)}")
        if removed_strings:
            result.logical_changes.append(f"Removed strings: {', '.join(removed_strings)}")

        for string_id in strings1 & strings2:
            if (
                analysis1["string_signatures"][string_id]
                != analysis2["string_signatures"][string_id]
            ):
                result.logical_changes.append(f"String '{string_id}' content modified")

        conditions1 = analysis1["condition_signatures"]
        conditions2 = analysis2["condition_signatures"]
        for condition_name in set(conditions1) & set(conditions2):
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

    def _detect_style_changes(
        self,
        ast1: YaraFile,
        ast2: YaraFile,
        result: ASTDiffResult,
    ) -> ASTDiffResult:
        """Backward-compatible hook retained for existing tests."""
        if ast1 is ast2:
            result.change_summary.setdefault("style_changes", len(result.style_only_changes))
            return result
        return result


class ASTFormatter:
    """AST-based code formatter using CodeGenerator."""

    def __init__(self) -> None:
        self.generator = CodeGenerator()
        self.pretty_printer = PrettyPrinter()

    def format_file(
        self,
        input_path: Path,
        output_path: Path | None = None,
        style: str = "default",
    ) -> tuple[bool, str]:
        try:
            with Path(input_path).open() as f:
                ast = Parser(f.read()).parse()
            formatted = self.format_ast(ast, style)
            if output_path:
                with Path(output_path).open("w") as f:
                    f.write(formatted)
                return True, f"Formatted file written to {output_path}"
            return True, formatted
        except Exception as exc:
            return False, f"Formatting error: {exc}"

    def format_ast(self, ast: Any, style: str = "default") -> str:
        if style == "compact":
            return self.generator.generate(ast)
        if style in ("pretty", "verbose"):
            self.pretty_printer = PrettyPrinter()
            return self.pretty_printer.pretty_print(ast)
        return self.pretty_printer.pretty_print(ast)

    def check_format(self, file_path: Path) -> tuple[bool, list[str]]:
        try:
            with Path(file_path).open() as f:
                original = f.read()
            formatted = self.pretty_printer.pretty_print(Parser(original).parse())
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
        except Exception as exc:
            return False, [f"Check error: {exc}"]
