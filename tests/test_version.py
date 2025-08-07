"""Test version functionality."""

from yaraast import (
    YARA_SYNTAX_VERSION,
    YARAAST_VERSION,
    YARAAST_VERSION_MAJOR,
    YARAAST_VERSION_MINOR,
    YARAAST_VERSION_PATCH,
    __version__,
    get_version_info,
    get_version_string,
)
from yaraast.version import YARAX_COMPATIBLE, YARAX_SYNTAX_VERSION


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

    # Check __version__ matches
    assert __version__ == YARAAST_VERSION

    # Check YARA syntax version
    assert isinstance(YARA_SYNTAX_VERSION, str)
    assert "." in YARA_SYNTAX_VERSION


def test_version_functions() -> None:
    """Test version helper functions."""
    # Test version string
    version_str = get_version_string()
    assert isinstance(version_str, str)
    assert "YARAAST" in version_str
    assert YARAAST_VERSION in version_str
    assert YARA_SYNTAX_VERSION in version_str

    # Test version info dict
    info = get_version_info()
    assert isinstance(info, dict)

    # Check structure
    assert "yaraast" in info
    assert "yara" in info
    assert "yarax" in info
    assert "build" in info

    # Check yaraast info
    assert info["yaraast"]["major"] == YARAAST_VERSION_MAJOR
    assert info["yaraast"]["minor"] == YARAAST_VERSION_MINOR
    assert info["yaraast"]["patch"] == YARAAST_VERSION_PATCH
    assert info["yaraast"]["version"] == YARAAST_VERSION

    # Check yarax info
    assert info["yarax"]["version"] == YARAX_SYNTAX_VERSION
    assert info["yarax"]["compatible"] == YARAX_COMPATIBLE


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
    assert yaraast_tuple == (1, 0, 0)  # Current version


if __name__ == "__main__":
    test_version_constants()
    test_version_functions()
    test_version_format()
    test_version_comparison()
    print("✓ All version tests passed")
