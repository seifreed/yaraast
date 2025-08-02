"""Version information for YARAAST."""

# YARAAST version
YARAAST_VERSION_MAJOR = 1
YARAAST_VERSION_MINOR = 0
YARAAST_VERSION_PATCH = 0
YARAAST_VERSION = f"{YARAAST_VERSION_MAJOR}.{YARAAST_VERSION_MINOR}.{YARAAST_VERSION_PATCH}"

# YARA syntax version we're compatible with
YARA_SYNTAX_VERSION = "4.5.0"
YARA_SYNTAX_VERSION_MAJOR = 4
YARA_SYNTAX_VERSION_MINOR = 5
YARA_SYNTAX_VERSION_PATCH = 0

# YARA-X compatibility version
YARAX_SYNTAX_VERSION = "0.4.0"
YARAX_COMPATIBLE = True

# Build information
BUILD_DATE = "2024-01-01"
BUILD_COMMIT = "unknown"


def get_version_string() -> str:
    """Get full version string."""
    return f"YARAAST {YARAAST_VERSION} (YARA {YARA_SYNTAX_VERSION} compatible)"


def get_version_info() -> dict:
    """Get version information as dictionary."""
    return {
        "yaraast": {
            "major": YARAAST_VERSION_MAJOR,
            "minor": YARAAST_VERSION_MINOR,
            "patch": YARAAST_VERSION_PATCH,
            "version": YARAAST_VERSION,
        },
        "yara": {
            "major": YARA_SYNTAX_VERSION_MAJOR,
            "minor": YARA_SYNTAX_VERSION_MINOR,
            "patch": YARA_SYNTAX_VERSION_PATCH,
            "version": YARA_SYNTAX_VERSION,
        },
        "yarax": {"version": YARAX_SYNTAX_VERSION, "compatible": YARAX_COMPATIBLE},
        "build": {"date": BUILD_DATE, "commit": BUILD_COMMIT},
    }
