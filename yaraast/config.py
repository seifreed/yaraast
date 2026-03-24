"""Centralized configuration constants for yaraast."""

from __future__ import annotations

# Parser configuration
DEFAULT_STREAMING_THRESHOLD_MB = 100
MAX_PARSER_ERRORS = 100

# Serialization configuration
YAML_DEFAULT_WIDTH = 120
JSON_DEFAULT_INDENT = 2

# LSP configuration
DEFAULT_DIAGNOSTICS_DEBOUNCE_MS = 75
