"""Include file resolver with path searching, caching, and cycle detection."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from yaraast.parser import Parser

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


@dataclass
class ResolvedFile:
    """Represents a resolved YARA file."""

    path: Path
    content: str
    ast: YaraFile
    checksum: str
    includes: list[ResolvedFile] = field(default_factory=list)

    def get_all_rules(self):
        """Get all rules including from includes."""
        rules = list(self.ast.rules)
        for include in self.includes:
            rules.extend(include.get_all_rules())
        return rules


class IncludeResolver:
    """Resolves YARA include statements with caching and cycle detection."""

    def __init__(self, search_paths: list[str] | None = None) -> None:
        """Initialize include resolver.

        Args:
            search_paths: List of directories to search for include files.
                         If None, uses current directory and YARA_INCLUDE_PATH env var.

        """
        self.search_paths = self._init_search_paths(search_paths)
        self.cache: dict[str, ResolvedFile] = {}
        self.resolution_stack: list[Path] = []
        self.parser = Parser()

    def _init_search_paths(self, search_paths: list[str] | None) -> list[Path]:
        """Initialize search paths from config and environment."""
        paths = []

        # Add provided paths
        if search_paths:
            paths.extend(Path(p).resolve() for p in search_paths)

        # Add current directory
        paths.append(Path.cwd())

        # Add paths from environment variable
        env_paths = os.environ.get("YARA_INCLUDE_PATH", "")
        if env_paths:
            for path in env_paths.split(os.pathsep):
                if path:
                    paths.append(Path(path).resolve())

        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for path in paths:
            if path not in seen:
                seen.add(path)
                unique_paths.append(path)

        return unique_paths

    def resolve(self, file_path: str, base_path: Path | None = None) -> ResolvedFile:
        """Alias for resolve_file for backward compatibility."""
        return self.resolve_file(file_path, base_path)

    def resolve_file(
        self,
        file_path: str,
        base_path: Path | None = None,
    ) -> ResolvedFile:
        """Resolve a YARA file and all its includes.

        Args:
            file_path: Path to the YARA file.
            base_path: Base path for relative includes (defaults to file's directory).

        Returns:
            ResolvedFile object with AST and resolved includes.

        Raises:
            FileNotFoundError: If file cannot be found.
            RecursionError: If circular include is detected.

        """
        # Find the file
        resolved_path = self._find_file(file_path, base_path)

        # Check cache
        cache_key = str(resolved_path)
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            # Verify checksum
            current_checksum = self._calculate_checksum(resolved_path)
            if cached.checksum == current_checksum:
                return cached

        # Check for circular includes
        if resolved_path in self.resolution_stack:
            cycle = " -> ".join(str(p) for p in self.resolution_stack)
            cycle += f" -> {resolved_path}"
            msg = f"Circular include detected: {cycle}"
            raise RecursionError(msg)

        # Add to resolution stack
        self.resolution_stack.append(resolved_path)

        try:
            # Read and parse file
            content = resolved_path.read_text()
            ast = self.parser.parse(content)
            checksum = self._calculate_checksum_from_content(content)

            # Create resolved file
            resolved = ResolvedFile(
                path=resolved_path,
                content=content,
                ast=ast,
                checksum=checksum,
            )

            # Resolve includes
            for include in ast.includes:
                try:
                    included_file = self.resolve_file(
                        include.path,
                        base_path=resolved_path.parent,
                    )
                    resolved.includes.append(included_file)
                except (FileNotFoundError, RecursionError):
                    # Log error but continue parsing other includes
                    pass

            # Cache the result
            self.cache[cache_key] = resolved

            return resolved

        finally:
            # Remove from resolution stack
            self.resolution_stack.pop()

    def _find_file(self, file_path: str, base_path: Path | None = None) -> Path:
        """Find a file in search paths.

        Args:
            file_path: Path to find (can be relative).
            base_path: Base path for relative paths.

        Returns:
            Resolved absolute path.

        Raises:
            FileNotFoundError: If file cannot be found.

        """
        path = Path(file_path)

        # If absolute and exists, return it
        if path.is_absolute() and path.exists():
            return path.resolve()

        # Search paths to try
        search_dirs = []

        # First try relative to base path
        if base_path:
            search_dirs.append(base_path)

        # Then try search paths
        search_dirs.extend(self.search_paths)

        # Try each search directory
        for search_dir in search_dirs:
            full_path = search_dir / path
            if full_path.exists():
                return full_path.resolve()

        # Not found
        searched = [str(d) for d in search_dirs]
        msg = f"Cannot find include file '{file_path}'. Searched in: {', '.join(searched)}"
        raise FileNotFoundError(
            msg,
        )

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate checksum of a file."""
        content = file_path.read_text()
        return self._calculate_checksum_from_content(content)

    def _calculate_checksum_from_content(self, content: str) -> str:
        """Calculate checksum from content."""
        return hashlib.sha256(content.encode()).hexdigest()

    def clear_cache(self) -> None:
        """Clear the file cache."""
        self.cache.clear()

    def get_all_resolved_files(self) -> list[ResolvedFile]:
        """Get all resolved files from cache."""
        return list(self.cache.values())

    def get_include_tree(self, file_path: str) -> dict:
        """Get include tree structure for a file.

        Returns:
            Dictionary representing the include tree.

        """
        resolved = self.resolve_file(file_path)
        return self._build_include_tree(resolved)

    def _build_include_tree(self, resolved: ResolvedFile) -> dict:
        """Build include tree structure."""
        tree = {"path": str(resolved.path), "includes": []}

        for include in resolved.includes:
            tree["includes"].append(self._build_include_tree(include))

        return tree
