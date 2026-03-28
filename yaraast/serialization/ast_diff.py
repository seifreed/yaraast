"""AST diff functionality for incremental versioning."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any

from yaraast.serialization.ast_diff_compare import compare_imports, compare_includes, compare_rules
from yaraast.serialization.ast_diff_hasher import AstHasher

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class DiffType(Enum):
    """Type of difference between AST nodes."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    MOVED = "moved"


@dataclass
class DiffNode:
    """Represents a difference in the AST."""

    path: str  # XPath-like path to the node
    diff_type: DiffType
    old_value: Any | None = None
    new_value: Any | None = None
    node_type: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiffResult:
    """Result of AST comparison."""

    old_ast_hash: str
    new_ast_hash: str
    differences: list[DiffNode] = field(default_factory=list)
    statistics: dict[str, int] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return len(self.differences) > 0

    @property
    def change_summary(self) -> dict[str, int]:
        """Get summary of changes by type."""
        summary = {diff_type.value: 0 for diff_type in DiffType}
        for diff in self.differences:
            summary[diff.diff_type.value] += 1
        return summary

    def get_changes_by_type(self, diff_type: DiffType) -> list[DiffNode]:
        """Get all changes of a specific type."""
        return [diff for diff in self.differences if diff.diff_type == diff_type]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "old_ast_hash": self.old_ast_hash,
            "new_ast_hash": self.new_ast_hash,
            "has_changes": self.has_changes,
            "change_summary": self.change_summary,
            "differences": [
                {
                    "path": diff.path,
                    "type": diff.diff_type.value,
                    "old_value": diff.old_value,
                    "new_value": diff.new_value,
                    "node_type": diff.node_type,
                    "details": diff.details,
                }
                for diff in self.differences
            ],
            "statistics": self.statistics,
        }


class AstDiff:
    """Compares two ASTs and produces incremental diffs."""

    def __init__(self) -> None:
        self.hasher = AstHasher()

    def compare(self, old_ast: YaraFile, new_ast: YaraFile) -> DiffResult:
        """Compare two ASTs and return differences."""
        old_hash = self.hasher.hash_ast(old_ast)
        new_hash = self.hasher.hash_ast(new_ast)

        result = DiffResult(old_ast_hash=old_hash, new_ast_hash=new_hash)

        if old_hash == new_hash:
            # ASTs are identical
            return result

        # Compare file-level elements
        compare_imports(old_ast.imports, new_ast.imports, result, DiffNode, DiffType)
        compare_includes(old_ast.includes, new_ast.includes, result, DiffNode, DiffType)
        compare_rules(old_ast.rules, new_ast.rules, result, self.hasher, DiffNode, DiffType)

        # Add statistics
        result.statistics = {
            "total_changes": len(result.differences),
            "old_rules_count": len(old_ast.rules),
            "new_rules_count": len(new_ast.rules),
            "old_imports_count": len(old_ast.imports),
            "new_imports_count": len(new_ast.imports),
        }

        return result

    def create_patch(
        self,
        diff_result: DiffResult,
        output_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Create a patch file from diff result."""
        patch = {
            "patch_format": "yaraast-diff-v1",
            "old_hash": diff_result.old_ast_hash,
            "new_hash": diff_result.new_ast_hash,
            "timestamp": int(time.time()),
            "changes": diff_result.to_dict(),
        }

        if output_path:
            import json

            with Path(output_path).open("w") as f:
                json.dump(patch, f, indent=2)

        return patch
