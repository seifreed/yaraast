"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Pytest configuration for benchmarking suite.

This module configures pytest-benchmark for automated
performance regression testing.
"""

from pathlib import Path
from typing import Any

import pytest

from yaraast.parser import Parser
from yaraast.performance.streaming_parser import StreamingParser


def pytest_configure(config: Any) -> None:
    """Configure pytest for benchmark tests."""
    config.addinivalue_line("markers", "benchmark: mark test as a benchmark test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


@pytest.fixture(scope="session")
def benchmark_dir() -> Path:
    """Provide the benchmarks directory path.

    Returns:
        Path to the benchmarks directory
    """
    return Path(__file__).parent


@pytest.fixture(scope="session")
def test_data_dir(benchmark_dir: Path) -> Path:
    """Provide the test data directory path.

    Returns:
        Path to the test_data directory
    """
    return benchmark_dir / "test_data"


@pytest.fixture(scope="session")
def results_dir(benchmark_dir: Path) -> Path:
    """Provide the results directory path.

    Returns:
        Path to the results directory
    """
    results = benchmark_dir / "results"
    results.mkdir(parents=True, exist_ok=True)
    return results


@pytest.fixture(scope="session")
def small_test_file(test_data_dir: Path) -> Path:
    """Provide a small test file for quick benchmarks.

    Returns:
        Path to small test file (5MB)
    """
    file_path = test_data_dir / "test_rules_5mb.yar"
    if not file_path.exists():
        pytest.skip(f"Test file not found: {file_path}")
    return file_path


@pytest.fixture(scope="session")
def medium_test_file(test_data_dir: Path) -> Path:
    """Provide a medium test file for benchmarks.

    Returns:
        Path to medium test file (10MB)
    """
    file_path = test_data_dir / "test_rules_10mb.yar"
    if not file_path.exists():
        pytest.skip(f"Test file not found: {file_path}")
    return file_path


@pytest.fixture(scope="session")
def large_test_file(test_data_dir: Path) -> Path:
    """Provide a large test file for stress testing.

    Returns:
        Path to large test file (20MB)
    """
    file_path = test_data_dir / "test_rules_20mb.yar"
    if not file_path.exists():
        pytest.skip(f"Test file not found: {file_path}")
    return file_path


@pytest.fixture(scope="function")
def standard_parser() -> type[Parser]:
    """Provide a fresh Parser instance.

    Returns:
        Parser class (not instance)
    """
    return Parser


@pytest.fixture(scope="function")
def streaming_parser() -> type[StreamingParser]:
    """Provide a fresh StreamingParser instance.

    Returns:
        StreamingParser class (not instance)
    """
    return StreamingParser
