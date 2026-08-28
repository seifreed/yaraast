"""High-level local project API."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from yaraast.check import check_path
from yaraast.diagnostics import DiagnosticResult
from yaraast.project_config import ProjectConfig
from yaraast.rule_testing import (
    RuleTestManifest,
    RuleTestResult,
    discover_manifests,
    discover_rule_sources,
    run_manifests,
    select_changed_manifests,
)

if TYPE_CHECKING:
    from yaraast.refactor import RefactorSession


@dataclass(frozen=True)
class Project:
    """A configured YARA repository rooted at a local directory."""

    root: Path
    config: ProjectConfig

    @classmethod
    def load(
        cls,
        root: str | Path = ".",
        *,
        config: str | Path | None = None,
        profile: str = "default",
    ) -> Project:
        """Load a project and its configuration."""
        project_root = Path(root)
        if not project_root.is_dir():
            raise ValueError(f"project root must be a directory: {project_root}")
        config_root = Path(config) if config is not None else project_root
        return cls(project_root, ProjectConfig.load(config_root, profile))

    def check(
        self,
        *,
        profile: str = "default",
        targets: tuple[str, ...] | None = None,
        compile_targets: bool = True,
    ) -> DiagnosticResult:
        """Run the repository check workflow."""
        config = (
            self.config
            if profile == self.config.profile
            else ProjectConfig.load(self.root, profile)
        )
        return check_path(
            self.root,
            config,
            profile=profile,
            targets=targets,
            compile_targets=compile_targets,
        )

    def test(
        self,
        *,
        engines: tuple[str, ...] | None = None,
        tests_path: str | Path | None = None,
        rules_path: str | Path | None = None,
        changed_from: str | None = None,
    ) -> RuleTestResult:
        """Run local fixture manifests against configured rule sources."""
        manifest_root = Path(tests_path) if tests_path is not None else self.root
        rule_root = Path(rules_path) if rules_path is not None else self.root
        manifests = tuple(RuleTestManifest.load(item) for item in discover_manifests(manifest_root))
        if changed_from is not None:
            manifests = select_changed_manifests(manifests, self.root, changed_from)
        sources = discover_rule_sources(rule_root)
        selected = engines or ("libyara", "yara-x")
        from yaraast.conformance.engines import LibyaraEngine, YaraXEngine

        references = tuple(
            item for item in (LibyaraEngine(), YaraXEngine()) if item.name in selected
        )
        return run_manifests(manifests, sources, engines=references)

    def edit(self) -> RefactorSession:
        """Return a lossless refactor session for this project."""
        from yaraast.refactor import RefactorSession

        return RefactorSession(self.root)
