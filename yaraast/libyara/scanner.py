"""Scanner using libyara for cross-validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from os import PathLike
import time
from typing import Any

from yaraast.libyara._availability import is_missing_yara_import
from yaraast.libyara._paths import path_exists, path_stat, require_file_path

try:
    import yara

    YARA_AVAILABLE = True
except ImportError as exc:
    if not is_missing_yara_import(exc):
        raise
    yara = None
    YARA_AVAILABLE = False


@dataclass
class MatchInfo:
    """Information about a rule match."""

    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[dict[str, Any]]

    @classmethod
    def from_yara_match(cls, match: Any) -> MatchInfo:
        """Create from yara match object."""
        return cls(
            rule=match.rule,
            namespace=match.namespace,
            tags=list(match.tags),
            meta=dict(match.meta),
            strings=(
                [
                    {
                        "offset": instance.offset,
                        "identifier": s.identifier,
                        "data": instance.matched_data,
                    }
                    for s in match.strings
                    for instance in (s.instances if s.instances else [])
                ]
                if hasattr(match, "strings")
                else []
            ),
        )


@dataclass
class ScanResult:
    """Result of scanning with libyara."""

    success: bool
    matches: list[MatchInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_time: float = 0.0
    data_size: int = 0

    @property
    def matched(self) -> bool:
        """Check if any rules matched."""
        return len(self.matches) > 0

    @property
    def matched_rules(self) -> list[str]:
        """Get list of matched rule names."""
        return [m.rule for m in self.matches]


class LibyaraScanner:
    """Scanner using libyara backend."""

    def __init__(self, timeout: int | None = None) -> None:
        """Initialize scanner.

        Args:
            timeout: Scan timeout in seconds

        """
        if not YARA_AVAILABLE:
            msg = "yara-python is not installed. Install it with: pip install yara-python"
            raise ImportError(
                msg,
            )

        self.timeout = timeout

    def scan_data(self, rules: Any, data: bytes, fast_mode: bool = False) -> ScanResult:
        """Scan data using compiled rules.

        Args:
            rules: Compiled yara.Rules object
            data: Data to scan
            fast_mode: Use fast mode (stop on first match)

        Returns:
            ScanResult with matches and timing

        """
        start_time = time.time()
        errors = []
        matches = []

        try:
            # Perform scan - only pass timeout if it's not None
            match_kwargs = {"data": data, "fast": fast_mode}
            if self.timeout is not None:
                match_kwargs["timeout"] = self.timeout
            yara_matches = rules.match(**match_kwargs)

            # Convert matches
            for match in yara_matches:
                matches.append(MatchInfo.from_yara_match(match))

            scan_time = time.time() - start_time

            return ScanResult(
                success=True,
                matches=matches,
                scan_time=scan_time,
                data_size=len(data),
            )

        except yara.TimeoutError:
            errors.append(f"Scan timeout after {self.timeout} seconds")
        except yara.Error as e:
            errors.append(f"Scan error: {e!s}")
        except Exception as e:
            errors.append(f"Unexpected error: {e!s}")

        scan_time = time.time() - start_time

        return ScanResult(
            success=False,
            errors=errors,
            scan_time=scan_time,
            data_size=len(data),
        )

    def scan_file(
        self,
        rules: Any,
        filepath: str | PathLike[str],
        fast_mode: bool = False,
    ) -> ScanResult:
        """Scan file using compiled rules.

        Args:
            rules: Compiled yara.Rules object
            filepath: Path to file to scan
            fast_mode: Use fast mode (stop on first match)

        Returns:
            ScanResult with matches and timing

        """
        try:
            filepath = require_file_path(filepath, "filepath")
        except (TypeError, ValueError) as exc:
            return ScanResult(success=False, errors=[str(exc)])

        try:
            file_exists = path_exists(filepath)
        except ValueError as exc:
            return ScanResult(success=False, errors=[str(exc)])

        if not file_exists:
            return ScanResult(success=False, errors=[f"File not found: {filepath}"])

        start_time = time.time()
        errors = []
        matches = []

        try:
            # Get file size
            file_size = path_stat(filepath).st_size

            # Perform scan - only pass timeout if it's not None
            match_kwargs = {"filepath": str(filepath), "fast": fast_mode}
            if self.timeout is not None:
                match_kwargs["timeout"] = self.timeout
            yara_matches = rules.match(**match_kwargs)

            # Convert matches
            for match in yara_matches:
                matches.append(MatchInfo.from_yara_match(match))

            scan_time = time.time() - start_time

            return ScanResult(
                success=True,
                matches=matches,
                scan_time=scan_time,
                data_size=file_size,
            )

        except yara.TimeoutError:
            errors.append(f"Scan timeout after {self.timeout} seconds")
        except yara.Error as e:
            errors.append(f"Scan error: {e!s}")
        except Exception as e:
            errors.append(f"Unexpected error: {e!s}")

        scan_time = time.time() - start_time

        return ScanResult(success=False, errors=errors, scan_time=scan_time)

    def scan_process(self, rules: Any, pid: int) -> ScanResult:
        """Scan process memory using compiled rules.

        Args:
            rules: Compiled yara.Rules object
            pid: Process ID to scan

        Returns:
            ScanResult with matches

        """
        start_time = time.time()
        errors = []
        matches = []

        try:
            # Perform scan
            yara_matches = rules.match(pid=pid)

            # Convert matches
            for match in yara_matches:
                matches.append(MatchInfo.from_yara_match(match))

            scan_time = time.time() - start_time

            return ScanResult(success=True, matches=matches, scan_time=scan_time)

        except yara.Error as e:
            errors.append(f"Process scan error: {e!s}")
        except Exception as e:
            errors.append(f"Unexpected error: {e!s}")

        scan_time = time.time() - start_time

        return ScanResult(success=False, errors=errors, scan_time=scan_time)
