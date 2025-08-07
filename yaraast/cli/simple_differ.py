"""Simple differ for YARA files."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from yaraast.codegen import CodeGenerator
from yaraast.parser import Parser


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
        """Diff two YARA file contents."""
        lines1 = content1.splitlines()
        lines2 = content2.splitlines()

        diff_lines = []
        added = 0
        removed = 0
        modified = 0

        # Simple line-by-line diff
        max_lines = max(len(lines1), len(lines2))

        for i in range(max_lines):
            if i >= len(lines1):
                # Line added in content2
                diff_lines.append(
                    DiffLine(
                        type=DiffType.ADD,
                        line_num=i + 1,
                        content=f"+ {lines2[i]}",
                        new_content=lines2[i],
                    ),
                )
                added += 1
            elif i >= len(lines2):
                # Line removed from content1
                diff_lines.append(
                    DiffLine(
                        type=DiffType.REMOVE,
                        line_num=i + 1,
                        content=f"- {lines1[i]}",
                        old_content=lines1[i],
                    ),
                )
                removed += 1
            elif lines1[i] != lines2[i]:
                # Line modified
                diff_lines.append(
                    DiffLine(
                        type=DiffType.MODIFY,
                        line_num=i + 1,
                        content=f"~ {lines2[i]}",
                        old_content=lines1[i],
                        new_content=lines2[i],
                    ),
                )
                modified += 1
            else:
                # Line unchanged (context)
                diff_lines.append(
                    DiffLine(
                        type=DiffType.CONTEXT,
                        line_num=i + 1,
                        content=f"  {lines1[i]}",
                        old_content=lines1[i],
                        new_content=lines1[i],
                    ),
                )

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

    def diff_files(self, file1: str | Path, file2: str | Path) -> DiffResult:
        """Diff two YARA files."""
        file1 = Path(file1)
        file2 = Path(file2)

        with open(file1) as f:
            content1 = f.read()

        with open(file2) as f:
            content2 = f.read()

        return self.diff(content1, content2)

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
    ) -> dict[str, DiffResult]:
        """Diff all YARA files in two directories."""
        dir1 = Path(dir1)
        dir2 = Path(dir2)

        results = {}

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
    """Diff tokens in two contents."""
    tokens1 = content1.split()
    tokens2 = content2.split()

    changes = []
    for token in set(tokens1) - set(tokens2):
        changes.append(f"- {token}")
    for token in set(tokens2) - set(tokens1):
        changes.append(f"+ {token}")

    return changes


def diff_ast(ast1: Any, ast2: Any) -> DiffResult:
    """Diff two ASTs."""
    differ = SimpleDiffer()
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
    format_diff(diff_result)
