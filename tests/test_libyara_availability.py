"""Real tests for libyara availability paths (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.compiler import LibyaraCompiler
from yaraast.libyara.scanner import YARA_AVAILABLE as SCANNER_AVAILABLE
from yaraast.libyara.scanner import LibyaraScanner


def test_libyara_compiler_import_error_when_missing() -> None:
    if COMPILER_AVAILABLE:
        pytest.skip("yara-python available; skipping ImportError check")
    with pytest.raises(ImportError):
        LibyaraCompiler()


def test_libyara_scanner_import_error_when_missing() -> None:
    if SCANNER_AVAILABLE:
        pytest.skip("yara-python available; skipping ImportError check")
    with pytest.raises(ImportError):
        LibyaraScanner()
