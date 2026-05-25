"""Tests for shared file pattern normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.shared.file_patterns import iter_matching_files, normalize_file_patterns


def test_normalize_file_patterns_rejects_non_string_entries(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="File patterns must be a string or iterable of strings"):
        normalize_file_patterns(cast(Any, [object()]))

    with pytest.raises(TypeError, match="File patterns must be a string or iterable of strings"):
        list(iter_matching_files(tmp_path, cast(Any, b"*.yar")))
