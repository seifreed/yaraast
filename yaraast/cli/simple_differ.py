"""Simple differ for YARA files."""

from __future__ import annotations

import difflib
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.parser import Parser


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
    old_content: str | None = None
    new_content: str | None = None


@dataclass
class DiffResult:
    """Result of a diff operation."""

    has_changes: bool
    lines: list[DiffLine]
    summary: dict[str, int]


class SimpleDiffer:
    """Simple differ for YARA files."""

    def __init__(self) -> None:
        """Initialize the differ."""
        self.parser = Parser()
        self.generator = CodeGenerator()

    def diff(self, content1: str, content2: str) -> DiffResult:
        """Diff two YARA file contents using LCS-based sequence matching."""
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
                old_content=lines1[i1 + idx],
                new_content=lines1[i1 + idx],
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
                    old_content=old_chunk[idx],
                    new_content=new_chunk[idx],
                ),
            )
            modified += 1
        elif idx < len(new_chunk):
            diff_lines.append(
                DiffLine(
                    type=DiffType.ADD,
                    line_num=line_num,
                    content=f"+ {new_chunk[idx]}",
                    new_content=new_chunk[idx],
                ),
            )
            added += 1
        else:
            diff_lines.append(
                DiffLine(
                    type=DiffType.REMOVE,
                    line_num=line_num,
                    content=f"- {old_chunk[idx]}",
                    old_content=old_chunk[idx],
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
                new_content=lines2[j1 + idx],
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
                old_content=lines1[i1 + idx],
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


class SimpleASTDiffer(SimpleDiffer):
    """Simplified AST differ for CLI use."""

    def __init__(self) -> None:
        super().__init__()

    def diff_files(self, file1: Path, file2: Path) -> ASTDiffResult:
        content1 = file1.read_text()
        content2 = file2.read_text()

        ast1 = self.parser.parse(content1)
        ast2 = self.parser.parse(content2)

        rules1 = {rule.name: rule for rule in ast1.rules}
        rules2 = {rule.name: rule for rule in ast2.rules}

        added_rules = sorted(set(rules2) - set(rules1))
        removed_rules = sorted(set(rules1) - set(rules2))

        modified_rules: list[str] = []
        for name in set(rules1) & set(rules2):
            if repr(rules1[name]) != repr(rules2[name]):
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

    def diff_ast(self, ast1: Any, ast2: Any) -> DiffResult:
        """Diff two ASTs by comparing their generated code."""
        code1 = self.generator.generate(ast1)
        code2 = self.generator.generate(ast2)

        return self.diff(code1, code2)

    def get_changes(self, content1: str, content2: str) -> list[str]:
        """Get a list of changes between two contents."""
        result = self.diff(content1, content2)

        changes = []
        for line in result.lines:
            if line.type != DiffType.CONTEXT:
                changes.append(line.content)

        return changes

    def diff_directories(
        self,
        dir1: str | Path,
        dir2: str | Path,
    ) -> dict[str, DiffResult | ASTDiffResult]:
        """Diff all YARA files in two directories."""
        dir1 = Path(dir1)
        dir2 = Path(dir2)

        results: dict[str, DiffResult | ASTDiffResult] = {}

        # Get all .yar files in both directories
        files1 = {p.relative_to(dir1) for p in dir1.glob("**/*.yar")}
        files2 = {p.relative_to(dir2) for p in dir2.glob("**/*.yar")}

        # Files in both directories
        common_files = files1 & files2
        for file in common_files:
            file1 = dir1 / file
            file2 = dir2 / file
            results[str(file)] = self.diff_files(file1, file2)

        # Files only in dir1 (removed)
        removed_files = files1 - files2
        for file in removed_files:
            file1 = dir1 / file
            with open(file1) as f:
                content = f.read()

            # Create a diff showing all lines as removed
            lines = content.splitlines()
            diff_lines = [
                DiffLine(
                    type=DiffType.REMOVE,
                    line_num=i + 1,
                    content=f"- {line}",
                    old_content=line,
                )
                for i, line in enumerate(lines)
            ]

            results[str(file)] = DiffResult(
                has_changes=True,
                lines=diff_lines,
                summary={"added": 0, "removed": len(lines), "modified": 0},
            )

        # Files only in dir2 (added)
        added_files = files2 - files1
        for file in added_files:
            file2 = dir2 / file
            with open(file2) as f:
                content = f.read()

            # Create a diff showing all lines as added
            lines = content.splitlines()
            diff_lines = [
                DiffLine(
                    type=DiffType.ADD,
                    line_num=i + 1,
                    content=f"+ {line}",
                    new_content=line,
                )
                for i, line in enumerate(lines)
            ]

            results[str(file)] = DiffResult(
                has_changes=True,
                lines=diff_lines,
                summary={"added": len(lines), "removed": 0, "modified": 0},
            )

        return results


def diff_lines(lines1: list[str], lines2: list[str]) -> list[DiffLine]:
    """Diff two lists of lines."""
    differ = SimpleDiffer()
    content1 = "\n".join(lines1)
    content2 = "\n".join(lines2)
    result = differ.diff(content1, content2)
    return result.lines


def diff_tokens(content1: str, content2: str) -> list[str]:
    """Diff tokens in two contents, accounting for frequency."""
    counts1 = Counter(content1.split())
    counts2 = Counter(content2.split())

    changes = []
    all_tokens = sorted(set(counts1) | set(counts2))
    for token in all_tokens:
        c1 = counts1.get(token, 0)
        c2 = counts2.get(token, 0)
        if c1 > c2:
            for _ in range(c1 - c2):
                changes.append(f"- {token}")
        elif c2 > c1:
            for _ in range(c2 - c1):
                changes.append(f"+ {token}")

    return changes


def diff_ast(ast1: Any, ast2: Any) -> DiffResult:
    """Diff two ASTs."""
    differ = SimpleASTDiffer()
    return differ.diff_ast(ast1, ast2)


def get_diff_summary(diff_result: DiffResult) -> dict[str, int]:
    """Get summary of diff result."""
    return diff_result.summary


def format_diff(diff_result: DiffResult) -> str:
    """Format diff result as string."""
    lines = []

    if not diff_result.has_changes:
        return "No changes"

    for line in diff_result.lines:
        if line.type != DiffType.CONTEXT:
            lines.append(line.content)

    return "\n".join(lines)


def print_diff(diff_result: DiffResult) -> None:
    """Print diff result to stdout."""
    print(format_diff(diff_result))
