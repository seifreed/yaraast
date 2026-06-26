"""Test version functionality."""

from yaraast.version import (
    YARA_SYNTAX_VERSION,
    YARAAST_VERSION,
    YARAAST_VERSION_MAJOR,
    YARAAST_VERSION_MINOR,
    YARAAST_VERSION_PATCH,
    YARAX_SYNTAX_VERSION,
)


def test_version_constants() -> None:
    """Test version constants are properly defined."""
    # Check version components
    assert isinstance(YARAAST_VERSION_MAJOR, int)
    assert isinstance(YARAAST_VERSION_MINOR, int)
    assert isinstance(YARAAST_VERSION_PATCH, int)

    # Check version string
    assert (
        f"{YARAAST_VERSION_MAJOR}.{YARAAST_VERSION_MINOR}.{YARAAST_VERSION_PATCH}"
        == YARAAST_VERSION
    )

    # Check YARA syntax version
    assert isinstance(YARA_SYNTAX_VERSION, str)
    assert "." in YARA_SYNTAX_VERSION


def test_version_format() -> None:
    """Test version string formats."""
    # Version should follow semantic versioning
    import re

    # Test YARAAST version format
    assert re.match(r"^\d+\.\d+\.\d+$", YARAAST_VERSION)

    # Test YARA syntax version format
    assert re.match(r"^\d+\.\d+\.\d+$", YARA_SYNTAX_VERSION)

    # Test YARA-X version format
    assert re.match(r"^\d+\.\d+\.\d+$", YARAX_SYNTAX_VERSION)


def test_version_comparison() -> None:
    """Test version can be used for comparisons."""
    # Create version tuples for comparison
    yaraast_tuple = (
        YARAAST_VERSION_MAJOR,
        YARAAST_VERSION_MINOR,
        YARAAST_VERSION_PATCH,
    )

    # Should be able to compare
    assert yaraast_tuple >= (0, 0, 0)
    assert yaraast_tuple <= (99, 99, 99)

    # Test specific version
    assert yaraast_tuple == (YARAAST_VERSION_MAJOR, YARAAST_VERSION_MINOR, YARAAST_VERSION_PATCH)


if __name__ == "__main__":
    test_version_constants()
    test_version_format()
    test_version_comparison()
    print("✓ All version tests passed")
