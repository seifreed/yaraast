"""Simple differ for YARA files."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import difflib
from enum import Enum
from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.parser import Parser
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.generator import YaraXGenerator


class DiffType(Enum):
    """Type of difference."""

    ADD = "+"
    REMOVE = "-"
    MODIFY = "~"
    CONTEXT = " "


@dataclass
class DiffLine:
    """Represents a line in the diff."""

    type: DiffType
    line_num: int
    content: str


@dataclass
class DiffResult:
    """Result of a diff operation."""

    has_changes: bool
    lines: list[DiffLine]
    summary: dict[str, int]


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        msg = f"{name} must be a string"
        raise TypeError(msg)
    return value


def _require_line_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(line, str) for line in value):
        msg = f"{name} must be a list of strings"
        raise TypeError(msg)
    return value


def _read_yara_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


class SimpleDiffer:
    """Simple differ for YARA files."""

    def __init__(
        self,
        parser: Parser | None = None,
        generator: CodeGenerator | None = None,
    ) -> None:
        """Initialize the differ."""
        self._parser_provided = parser is not None
        self.parser = parser or Parser()
        self.generator = generator or YaraXGenerator()

    def diff(self, content1: str, content2: str) -> DiffResult:
        """Diff two YARA file contents using LCS-based sequence matching."""
        content1 = _require_text(content1, "content1")
        content2 = _require_text(content2, "content2")
        lines1 = content1.splitlines()
        lines2 = content2.splitlines()

        diff_lines: list[DiffLine] = []
        added = 0
        removed = 0
        modified = 0

        matcher = difflib.SequenceMatcher(None, lines1, lines2)
        line_num = 0

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                new_lines, line_num = _process_equal(lines1, i1, i2, line_num)
                diff_lines.extend(new_lines)
            elif tag == "replace":
                new_lines, line_num, a, r, m = _process_replace(
                    lines1, lines2, i1, i2, j1, j2, line_num
                )
                diff_lines.extend(new_lines)
                added += a
                removed += r
                modified += m
            elif tag == "insert":
                new_lines, line_num, a = _process_insert(lines2, j1, j2, line_num)
                diff_lines.extend(new_lines)
                added += a
            elif tag == "delete":
                new_lines, line_num, r = _process_delete(lines1, i1, i2, line_num)
                diff_lines.extend(new_lines)
                removed += r

        has_changes = added > 0 or removed > 0 or modified > 0

        return DiffResult(
            has_changes=has_changes,
            lines=diff_lines,
            summary={
                "added": added,
                "removed": removed,
                "modified": modified,
                "total_changes": added + removed + modified,
            },
        )


def _process_equal(
    lines1: list[str], i1: int, i2: int, line_num: int
) -> tuple[list[DiffLine], int]:
    """Process an 'equal' opcode block, returning context lines."""
    diff_lines: list[DiffLine] = []
    for idx in range(i2 - i1):
        line_num += 1
        diff_lines.append(
            DiffLine(
                type=DiffType.CONTEXT,
                line_num=line_num,
                content=f"  {lines1[i1 + idx]}",
            ),
        )
    return diff_lines, line_num


def _process_replace(
    lines1: list[str],
    lines2: list[str],
    i1: int,
    i2: int,
    j1: int,
    j2: int,
    line_num: int,
) -> tuple[list[DiffLine], int, int, int, int]:
    """Process a 'replace' opcode block, returning diff lines and counts."""
    diff_lines: list[DiffLine] = []
    added = 0
    removed = 0
    modified = 0
    old_chunk = lines1[i1:i2]
    new_chunk = lines2[j1:j2]
    for idx in range(max(len(old_chunk), len(new_chunk))):
        line_num += 1
        if idx < len(old_chunk) and idx < len(new_chunk):
            diff_lines.append(
                DiffLine(
                    type=DiffType.MODIFY,
                    line_num=line_num,
                    content=f"~ {new_chunk[idx]}",
                ),
            )
            modified += 1
        elif idx < len(new_chunk):
            diff_lines.append(
                DiffLine(
                    type=DiffType.ADD,
                    line_num=line_num,
                    content=f"+ {new_chunk[idx]}",
                ),
            )
            added += 1
        else:
            diff_lines.append(
                DiffLine(
                    type=DiffType.REMOVE,
                    line_num=line_num,
                    content=f"- {old_chunk[idx]}",
                ),
            )
            removed += 1
    return diff_lines, line_num, added, removed, modified


def _process_insert(
    lines2: list[str], j1: int, j2: int, line_num: int
) -> tuple[list[DiffLine], int, int]:
    """Process an 'insert' opcode block, returning added lines."""
    diff_lines: list[DiffLine] = []
    count = j2 - j1
    for idx in range(count):
        line_num += 1
        diff_lines.append(
                DiffLine(
                    type=DiffType.ADD,
                    line_num=line_num,
                    content=f"+ {lines2[j1 + idx]}",
                ),
            )
    return diff_lines, line_num, count


def _process_delete(
    lines1: list[str], i1: int, i2: int, line_num: int
) -> tuple[list[DiffLine], int, int]:
    """Process a 'delete' opcode block, returning removed lines."""
    diff_lines: list[DiffLine] = []
    count = i2 - i1
    for idx in range(count):
        line_num += 1
        diff_lines.append(
                DiffLine(
                    type=DiffType.REMOVE,
                    line_num=line_num,
                    content=f"- {lines1[i1 + idx]}",
                ),
            )
    return diff_lines, line_num, count


@dataclass
class ASTDiffResult:
    """Result of an AST diff operation."""

    has_changes: bool
    change_summary: dict[str, int]
    added_rules: list[str]
    removed_rules: list[str]
    modified_rules: list[str]
    logical_changes: list[str]
    structural_changes: list[str]
    style_only_changes: list[str]


def _rule_occurrence_names(rules1: list[Rule], rules2: list[Rule]) -> set[str]:
    counts1 = Counter(rule.name for rule in rules1)
    counts2 = Counter(rule.name for rule in rules2)
    return {
        name
        for name in set(counts1) | set(counts2)
        if counts1.get(name, 0) > 1 or counts2.get(name, 0) > 1
    }


def _rule_occurrence_map(rules: list[Rule], occurrence_names: set[str]) -> dict[str, Rule]:
    seen: defaultdict[str, int] = defaultdict(int)
    result: dict[str, Rule] = {}

    for rule in rules:
        if rule.name not in occurrence_names:
            result[rule.name] = rule
            continue

        seen[rule.name] += 1
        result[f"{rule.name}#{seen[rule.name]}"] = rule

    return result


def _rule_signature(rule: Rule, generator: CodeGenerator) -> str:
    return generator.generate(YaraFile(rules=[rule]))


class SimpleASTDiffer(SimpleDiffer):
    """Simplified AST differ for CLI use."""

    def __init__(
        self,
        parser: Parser | None = None,
        generator: CodeGenerator | None = None,
    ) -> None:
        super().__init__(parser=parser, generator=generator)

    def diff_files(self, file1: Path, file2: Path) -> ASTDiffResult:
        content1 = _read_yara_text_file(file1)
        content2 = _read_yara_text_file(file2)

        if self._parser_provided:
            ast1 = self.parser.parse(content1)
            ast2 = self.parser.parse(content2)
        else:
            ast1 = parse_yara_source(content1)
            ast2 = parse_yara_source(content2)

        occurrence_names = _rule_occurrence_names(ast1.rules, ast2.rules)
        rules1 = _rule_occurrence_map(ast1.rules, occurrence_names)
        rules2 = _rule_occurrence_map(ast2.rules, occurrence_names)

        added_rules = sorted(set(rules2) - set(rules1))
        removed_rules = sorted(set(rules1) - set(rules2))

        modified_rules: list[str] = []
        for name in sorted(set(rules1) & set(rules2)):
            if _rule_signature(rules1[name], self.generator) != _rule_signature(
                rules2[name], self.generator
            ):
                modified_rules.append(name)

        logical_changes = []
        for name in added_rules:
            logical_changes.append(f"Rule added: {name}")
        for name in removed_rules:
            logical_changes.append(f"Rule removed: {name}")
        for name in modified_rules:
            logical_changes.append(f"Rule modified: {name}")

        change_summary = {
            "added_rules": len(added_rules),
            "removed_rules": len(removed_rules),
            "modified_rules": len(modified_rules),
        }

        has_changes = bool(added_rules or removed_rules or modified_rules)

        return ASTDiffResult(
            has_changes=has_changes,
            change_summary=change_summary,
            added_rules=added_rules,
            removed_rules=removed_rules,
            modified_rules=modified_rules,
            logical_changes=logical_changes,
            structural_changes=[],
            style_only_changes=[],
        )

    def diff_ast(self, ast1: YaraFile, ast2: YaraFile) -> DiffResult:
        """Diff two ASTs by comparing their generated code."""
        code1 = self.generator.generate(ast1)
        code2 = self.generator.generate(ast2)

        return self.diff(code1, code2)

