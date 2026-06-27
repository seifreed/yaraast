"""Include file resolver with path searching, caching, and cycle detection."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import os
from os import PathLike, fspath
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.parser.source import parse_yara_source
from yaraast.shared.path_safety import (
    path_has_symlink_ancestor,
    path_is_symlink,
    path_is_within_directory,
)

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


@dataclass
class ResolvedFile:
    """Represents a resolved YARA file."""

    path: Path
    content: str
    ast: YaraFile
    checksum: str
    includes: list[ResolvedFile] = field(default_factory=list)
    include_path_map: dict[str, Path] = field(default_factory=dict)

    def get_all_rules(self) -> list[Rule]:
        """Get all rules including from includes."""
        rules = list(self.ast.rules)
        for include in self.includes:
            rules.extend(include.get_all_rules())
        return rules


def _read_yara_text(file_path: Path, *, is_include: bool) -> str:
    try:
        if path_is_symlink(file_path):
            if is_include:
                msg = "YARA include file must not traverse a symlink"
            else:
                msg = "YARA file must not traverse a symlink"
            raise ValueError(msg)
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        if is_include:
            msg = "YARA include file must contain valid UTF-8 text"
        else:
            msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def _path_access_error(path: Path) -> ValueError:
    msg = f"path could not be accessed: {path}"
    return ValueError(msg)


def _path_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError as exc:
        raise _path_access_error(path) from exc


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

    def _init_search_paths(self, search_paths: list[str] | None) -> list[Path]:
        """Initialize search paths from config and environment."""
        paths: list[Path] = []

        # Add provided paths
        if search_paths is not None:
            if not isinstance(search_paths, list) or not all(
                isinstance(search_path, str) for search_path in search_paths
            ):
                msg = "IncludeResolver search_paths must be a list of strings"
                raise TypeError(msg)
            if any(not search_path.strip() for search_path in search_paths):
                msg = "IncludeResolver search_paths must not contain empty paths"
                raise ValueError(msg)
            paths.extend(self._normalize_search_path(p) for p in search_paths)
        else:
            # Add current directory only for the default search path set.
            paths.append(Path.cwd())

        # Add paths from environment variable
        env_paths = os.environ.get("YARA_INCLUDE_PATH", "")
        if env_paths:
            env_path_entries = env_paths.split(os.pathsep)
            if any(not env_path.strip() for env_path in env_path_entries):
                msg = "YARA_INCLUDE_PATH must not contain empty paths"
                raise ValueError(msg)
            paths.extend(self._normalize_search_path(env_path) for env_path in env_path_entries)

        # Remove duplicates while preserving order
        seen: set[Path] = set()
        unique_paths: list[Path] = []
        for candidate_path in paths:
            if candidate_path not in seen:
                seen.add(candidate_path)
                unique_paths.append(candidate_path)

        return unique_paths

    def _normalize_search_path(self, search_path: str) -> Path:
        path = Path(search_path)
        try:
            if path.is_symlink() or path_has_symlink_ancestor(path):
                msg = "IncludeResolver search paths must not be symlinks"
                raise ValueError(msg)
        except OSError as exc:
            raise _path_access_error(path) from exc
        return path.resolve()

    def resolve_file(
        self,
        file_path: str | PathLike[str],
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
        resolved_path = self._find_file(file_path, base_path)
        is_include = base_path is not None
        cache_key = str(resolved_path)
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            current_checksum = self._calculate_checksum(resolved_path, is_include=is_include)
            if (
                cached.checksum == current_checksum
                and self._all_declared_includes_resolved(cached)
                and self._includes_unchanged(cached)
            ):
                return deepcopy(cached)

        if resolved_path in self.resolution_stack:
            cycle = " -> ".join(str(p) for p in self.resolution_stack)
            cycle += f" -> {resolved_path}"
            msg = f"Circular include detected: {cycle}"
            raise RecursionError(msg)

        self.resolution_stack.append(resolved_path)
        try:
            return deepcopy(
                self._parse_and_resolve(
                    resolved_path,
                    cache_key,
                    is_include=is_include,
                )
            )
        finally:
            self.resolution_stack.pop()

    def _parse_and_resolve(
        self,
        resolved_path: Path,
        cache_key: str,
        *,
        is_include: bool,
    ) -> ResolvedFile:
        """Parse file and recursively resolve its includes."""
        content = _read_yara_text(resolved_path, is_include=is_include)
        ast = parse_yara_source(content)
        checksum = self._calculate_checksum_from_content(content)

        resolved = ResolvedFile(
            path=resolved_path,
            content=content,
            ast=ast,
            checksum=checksum,
        )

        for include in ast.includes:
            try:
                included_file = self.resolve_file(
                    include.path,
                    base_path=resolved_path.parent,
                )
                resolved.includes.append(included_file)
                resolved.include_path_map[include.path] = included_file.path
            except RecursionError:
                raise

        self.cache[cache_key] = resolved
        return resolved

    def _find_file(self, file_path: str | PathLike[str], base_path: Path | None = None) -> Path:
        """Find a file in search paths.

        Args:
            file_path: Path to find (can be relative).
            base_path: Base path for relative paths.

        Returns:
            Resolved absolute path.

        Raises:
            FileNotFoundError: If file cannot be found.

        """
        file_path_text = self._require_file_path(file_path)
        path = Path(file_path_text)

        # Absolute include paths are rejected; resolution must stay within the
        # including file's directory or the configured search paths.
        if base_path is not None and path.is_absolute():
            searched = self._format_searched_directories([base_path, *self.search_paths])
            msg = f"Cannot find include file '{file_path_text}'. Searched in: {searched}"
            raise FileNotFoundError(msg)

        # If absolute and exists, return it
        if path.is_absolute() and _path_is_file(path):
            if path_is_symlink(path) or path_has_symlink_ancestor(path):
                msg = "file_path must not traverse a symlink"
                raise ValueError(msg)
            return path.absolute()

        # First try relative to base path
        if base_path:
            full_path = base_path / path
            if _path_is_file(full_path):
                if path_is_symlink(full_path) or path_has_symlink_ancestor(full_path):
                    msg = "file_path must not traverse a symlink"
                    raise ValueError(msg)
                resolved = full_path.resolve()
                if path_is_within_directory(resolved, base_path):
                    return full_path.absolute()

        # Then try search paths
        for search_dir in self.search_paths:
            full_path = search_dir / path
            if _path_is_file(full_path):
                if path_is_symlink(full_path) or path_has_symlink_ancestor(full_path):
                    msg = "file_path must not traverse a symlink"
                    raise ValueError(msg)
                resolved = full_path.resolve()
                # Prevent path traversal — resolved path must be within search directory
                try:
                    resolved.relative_to(search_dir.resolve())
                except ValueError:
                    continue  # Skip paths that escape the search directory
                return full_path.absolute()

        # Not found
        search_dirs = [base_path, *self.search_paths] if base_path else list(self.search_paths)
        searched = self._format_searched_directories(search_dirs)
        if base_path is None:
            msg = f"Cannot find YARA file '{file_path_text}'. Searched in: {searched}"
        else:
            msg = f"Cannot find include file '{file_path_text}'. Searched in: {searched}"
        raise FileNotFoundError(
            msg,
        )

    def _format_searched_directories(self, search_dirs: Sequence[Path | None]) -> str:
        seen: set[Path] = set()
        searched: list[str] = []
        for search_dir in search_dirs:
            if search_dir is None or search_dir in seen:
                continue
            seen.add(search_dir)
            searched.append(str(search_dir))
        return ", ".join(searched)

    def _require_file_path(self, file_path: object) -> str:
        if isinstance(file_path, bool | bytes) or not isinstance(file_path, str | PathLike):
            msg = "file_path must be a string or path-like object"
            raise TypeError(msg)
        raw_path = fspath(file_path)
        if not isinstance(raw_path, str):
            msg = "file_path must be a string or path-like object"
            raise TypeError(msg)
        if not raw_path.strip():
            msg = "file_path must not be empty"
            raise ValueError(msg)
        if "\x00" in raw_path:
            msg = "file_path must not contain null bytes"
            raise ValueError(msg)
        path = Path(raw_path)
        if path_is_symlink(path):
            msg = "file_path must not traverse a symlink"
            raise ValueError(msg)
        return raw_path

    def _includes_unchanged(self, resolved: ResolvedFile) -> bool:
        """Check if all included files still have the same checksum."""
        for included in resolved.includes:
            try:
                if not self._all_declared_includes_resolved(included):
                    return False
                current = self._calculate_checksum(included.path, is_include=True)
                if current != included.checksum:
                    return False
                # Recursively check nested includes
                if not self._includes_unchanged(included):
                    return False
            except OSError:
                return False
        return True

    def _all_declared_includes_resolved(self, resolved: ResolvedFile) -> bool:
        """Check whether cached resolution covered every include declaration."""
        return len(resolved.includes) == len(resolved.ast.includes)

    def _calculate_checksum(self, file_path: Path, *, is_include: bool) -> str:
        """Calculate checksum of a file."""
        content = _read_yara_text(file_path, is_include=is_include)
        return self._calculate_checksum_from_content(content)

    def _calculate_checksum_from_content(self, content: str) -> str:
        """Calculate checksum from content."""
        return hashlib.sha256(content.encode()).hexdigest()

    def clear_cache(self) -> None:
        """Clear the file cache."""
        self.cache.clear()

    def get_all_resolved_files(self) -> list[ResolvedFile]:
        """Get all resolved files from cache."""
        return [deepcopy(resolved) for resolved in self.cache.values()]

    def get_include_tree(self, file_path: str | PathLike[str]) -> dict[str, Any]:
        """Get include tree structure for a file.

        Returns:
            Dictionary representing the include tree.

        """
        resolved = self.resolve_file(file_path)
        return self._build_include_tree(resolved)

    def _build_include_tree(self, resolved: ResolvedFile) -> dict[str, Any]:
        """Build include tree structure."""
        includes: list[dict[str, Any]] = []
        tree: dict[str, Any] = {"path": str(resolved.path), "includes": includes}

        for include in resolved.includes:
            includes.append(self._build_include_tree(include))

        return tree
