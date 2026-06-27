# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression coverage for three modules toward 100%.

Targets:
  yaraast/metrics/dependency_graph_helpers.py  — lines 27-28, 68-69
  yaraast/shared/local_scope.py                — lines 35-36
  yaraast/visitor/base_helpers.py              — Protocol stub branch exits
                                                 (15->exit, 17->exit, 19->exit, 21->exit)

All tests exercise real production code paths without mocks, test doubles,
or artificial scaffolding.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from yaraast.metrics.dependency_graph_helpers import _path_is_dir, require_output_path
from yaraast.shared.local_scope import validate_local_identifier
from yaraast.visitor.base_helpers import VisitorHelperProtocol

# ---------------------------------------------------------------------------
# yaraast/metrics/dependency_graph_helpers.py — lines 27-28
#
# _path_is_dir wraps path.is_dir() in a try/except OSError block and
# re-raises as ValueError via _path_access_error.  On POSIX systems the
# OS raises OSError(ENAMETOOLONG) when the filename component exceeds
# NAME_MAX (255 bytes on HFS+/APFS, ext4, etc.).  A 4096-character
# single-segment path name reliably triggers this on macOS and Linux
# without any privilege escalation or filesystem mutation.
# ---------------------------------------------------------------------------


def test_path_is_dir_raises_value_error_on_os_error_from_name_too_long() -> None:
    """_path_is_dir re-raises OSError as ValueError via _path_access_error.

    Passing a filename whose segment length exceeds the OS limit causes
    path.is_dir() to raise OSError(ENAMETOOLONG).  _path_is_dir catches that
    and raises ValueError instead (lines 27-28).
    """
    # Arrange: a single-component path name far beyond the 255-byte POSIX limit
    oversized_segment = "z" * 4096
    path = Path("/") / oversized_segment

    # Act & Assert: OSError from the OS is re-raised as ValueError
    with pytest.raises(ValueError, match="path could not be accessed"):
        _path_is_dir(path)


# ---------------------------------------------------------------------------
# yaraast/metrics/dependency_graph_helpers.py — lines 68-69
#
# require_output_path calls os.fspath() on its argument after the initial
# isinstance guard.  The guard accepts any os.PathLike, but os.fspath()
# on a PathLike[bytes] returns bytes rather than str.  The secondary
# isinstance(raw_path, str) check on lines 67-69 catches this case and
# raises TypeError to reject bytes-backed paths as unsupported.
# ---------------------------------------------------------------------------


class _BytesBackedPath(os.PathLike[bytes]):
    """A PathLike whose __fspath__ returns bytes, mimicking os.fsencode output."""

    def __fspath__(self) -> bytes:
        return b"/tmp/output.yar"


def test_require_output_path_raises_type_error_for_bytes_backed_path_like() -> None:
    """require_output_path rejects a PathLike[bytes] at the fspath str-check.

    os.fspath() on a bytes-returning PathLike yields bytes, not str.  The
    guard at lines 67-69 in require_output_path detects this and raises
    TypeError so that only text paths are accepted (lines 68-69).
    """
    # Arrange: a PathLike whose __fspath__ returns bytes (not str)
    bytes_path = _BytesBackedPath()

    # Act & Assert: TypeError from the non-str raw path check
    with pytest.raises(TypeError, match="output_path must be a file path"):
        require_output_path(bytes_path)


def test_require_output_path_custom_name_appears_in_bytes_backed_error() -> None:
    """The custom 'name' parameter surfaces in the TypeError message for bytes paths.

    This exercises the same lines 68-69 with a non-default name to confirm
    the message template substitutes the parameter correctly.
    """
    # Arrange
    bytes_path = _BytesBackedPath()

    # Act & Assert
    with pytest.raises(TypeError, match="destination must be a file path"):
        require_output_path(bytes_path, name="destination")


def test_require_output_path_rejects_null_byte_string() -> None:
    """require_output_path must reject embedded null bytes before Path() use."""
    with pytest.raises(ValueError, match="output_path must not contain null bytes"):
        require_output_path("\x00broken")


# ---------------------------------------------------------------------------
# yaraast/shared/local_scope.py — lines 35-36
#
# validate_local_identifier has its own isinstance(name, str) guard at
# lines 34-36 that is independent of the matching guard in
# local_name_variants (lines 51-53).  When local_name_variants is called
# with a valid string, its outer guard intercepts invalid input before
# forwarding to validate_local_identifier.  Lines 35-36 are therefore
# only reachable by calling validate_local_identifier directly with a
# non-string argument.
# ---------------------------------------------------------------------------


def test_validate_local_identifier_raises_type_error_for_integer_argument() -> None:
    """validate_local_identifier rejects a non-string via its own isinstance guard.

    Passing an integer to validate_local_identifier triggers the TypeError
    branch at lines 34-36 that is unreachable through local_name_variants
    (which has a matching but separate guard that intercepts first).
    """
    # Arrange: a plain integer — a realistic mistake when building names
    # programmatically from numeric loop indices
    numeric_name: object = 7

    # Act & Assert: TypeError from validate_local_identifier's own guard
    with pytest.raises(TypeError, match="Local variable name must be a string"):
        validate_local_identifier(numeric_name)


def test_validate_local_identifier_raises_type_error_for_none_argument() -> None:
    """validate_local_identifier rejects None via its own isinstance guard (lines 35-36).

    None is a common sentinel that could accidentally be passed when the
    caller omits a loop variable name.  This exercises the same lines 35-36
    with a different input type for completeness.
    """
    # Arrange
    none_name: object = None

    # Act & Assert
    with pytest.raises(TypeError, match="Local variable name must be a string"):
        validate_local_identifier(none_name)


def test_validate_local_identifier_raises_type_error_for_list_argument() -> None:
    """validate_local_identifier rejects a list via lines 35-36.

    A list could arise when a caller unpacks a multi-variable declaration
    incorrectly and passes the whole list to a single-name validator.
    """
    # Arrange
    list_name: object = ["i", "j"]

    # Act & Assert
    with pytest.raises(TypeError, match="Local variable name must be a string"):
        validate_local_identifier(list_name)


# ---------------------------------------------------------------------------
# yaraast/visitor/base_helpers.py — Protocol stub branch exits
# (15->exit, 17->exit, 19->exit, 21->exit)
#
# VisitorHelperProtocol is a structural typing Protocol.  Its stub methods
# use the Ellipsis body ("..."), which Python 3.13 compiles to RETURN_CONST
# None.  Coverage's branch tracker records a "->exit" branch for each stub
# function that was never called.  Because Protocol classes cannot be
# instantiated, the only way to exercise these branches is through direct
# unbound function calls on the Protocol class itself.
#
# The calls below confirm:
#   1. The branch exits are reachable (not genuinely dead code).
#   2. The stubs return None and do not raise when called.
#   3. Protocol cannot be instantiated (the normal runtime boundary).
# ---------------------------------------------------------------------------


def test_visitor_helper_protocol_noop_stub_is_callable_as_unbound_function() -> None:
    """VisitorHelperProtocol._noop stub body executes and returns None (line 15->exit).

    Calling the unbound stub function directly exercises the branch from
    function entry to exit that coverage tracks as '15->exit'.  The stub
    returns None because the Ellipsis body compiles to RETURN_CONST None in
    Python 3.13.
    """
    # Act: direct unbound call with a synthetic self placeholder; capture via
    # a generic callable cast so mypy does not constrain the return type.
    stub: object = VisitorHelperProtocol._noop
    result = (stub)(None)  # type: ignore[operator]

    # Assert: stub body returns None
    assert result is None


def test_visitor_helper_protocol_visit_all_stub_is_callable_as_unbound_function() -> None:
    """VisitorHelperProtocol._visit_all stub body executes and returns None (17->exit)."""
    # Act: the stub is annotated -> None; cast to object to capture without error
    stub: object = VisitorHelperProtocol._visit_all
    result = (stub)(None, [])  # type: ignore[operator]

    # Assert
    assert result is None


def test_visitor_helper_protocol_visit_if_stub_is_callable_as_unbound_function() -> None:
    """VisitorHelperProtocol._visit_if stub body executes and returns None (19->exit)."""
    # Act
    stub: object = VisitorHelperProtocol._visit_if
    result = (stub)(None, None)  # type: ignore[operator]

    # Assert
    assert result is None


def test_visitor_helper_protocol_visit_value_stub_is_callable_as_unbound_function() -> None:
    """VisitorHelperProtocol._visit_value stub body executes and returns None (21->exit)."""
    # Act
    stub: object = VisitorHelperProtocol._visit_value
    result = (stub)(None, None)  # type: ignore[operator]

    # Assert
    assert result is None


def test_visitor_helper_protocol_cannot_be_instantiated_at_runtime() -> None:
    """VisitorHelperProtocol raises TypeError on direct instantiation.

    This confirms the structural-only nature of the Protocol: the stub
    branch exits are only reachable through unbound direct calls, not
    through normal Protocol usage.
    """
    # Route through a plain `type` binding so mypy does not raise a static
    # error at this call site (Protocol types are not callable in typed code).
    protocol_cls: type = VisitorHelperProtocol

    with pytest.raises(TypeError, match="Protocols cannot be instantiated"):
        protocol_cls()
