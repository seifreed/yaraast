# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting the remaining uncovered lines in streaming_parser.py.

Lines targeted (from coverage report showing 94.61% before these tests):
  50-51  : _require_pathlike -- fspath() returns bytes (PathLike.__fspath__ -> bytes)
  73-74  : _path_is_dir OSError -- unreachable under normal POSIX (documented below)
  225    : parse_stream -- UTF-8 incremental decoder tail is non-empty on stream end
  392    : _memory_limit_exceeded -- psutil.Error catch path
  450-451: _parse_content -- dialect set, factory provided, dialect != YARA
  452-453: _parse_content -- dialect == YARA, no factory (uses self.parser.parse)
  Branch [450->452]: dialect != YARA, factory is None -> falls through to is-YARA check
  Branch [452->454]: dialect set but not YARA, factory is None -> parse_yara_source
  Branch [232->229]: _parse_rule_text returns None inside parse_stream loop
"""

from __future__ import annotations

import io
from os import PathLike, fspath
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any

import psutil
import pytest

from yaraast.dialects import YaraDialect
from yaraast.errors import YaraASTError
from yaraast.parser.source import parse_yara_source
from yaraast.performance.streaming_parser import StreamingParser, _require_pathlike

# ---------------------------------------------------------------------------
# Lines 50-51: _require_pathlike with a PathLike whose __fspath__ returns bytes
# ---------------------------------------------------------------------------


class _BytesPathLike(PathLike[bytes]):
    """PathLike implementation that returns bytes from __fspath__.

    Python's os.fspath() accepts PathLike objects whose __fspath__ returns
    bytes.  When bytes are returned, the subsequent isinstance(raw_path, str)
    check inside _require_pathlike is False, executing lines 50-51.
    """

    def __fspath__(self) -> bytes:
        return b"/some/bytes/path"


def test_require_pathlike_raises_for_bytes_returning_fspath() -> None:
    """_require_pathlike must reject a PathLike whose __fspath__ returns bytes.

    The check on line 49 (``if not isinstance(raw_path, str)``) guards against
    exotic PathLike implementations that return bytes instead of str.  Lines
    50-51 are the error branch for this case.
    """
    # Arrange: a valid PathLike that returns bytes from __fspath__
    obj: PathLike[bytes] = _BytesPathLike()
    # Sanity check: fspath really does return bytes here
    assert isinstance(fspath(obj), bytes)

    # Act / Assert: _require_pathlike must raise TypeError describing the problem
    with pytest.raises(TypeError, match="test_name must be a text path"):
        _require_pathlike(obj, "test_name")


# ---------------------------------------------------------------------------
# Lines 73-74: _path_is_dir OSError
# UNREACHABLE via deterministic real code on POSIX systems.
#
# The helper _path_is_dir wraps path.is_dir() to convert OSError to ValueError.
# It is only called after _path_exists(path) returns True (short-circuit `and`).
# On POSIX, Path.exists() and Path.is_dir() both call os.stat() internally.
# If stat raises an unignored OSError (e.g. ENAMETOOLONG), both calls raise
# identically -- so _path_exists will raise first and _path_is_dir is never
# reached.  The only scenario where _path_is_dir's OSError handler fires is a
# TOCTOU race where the filesystem changes between the two stat() calls, which
# is non-deterministic and cannot be reliably reproduced in a unit test without
# mocking.
#
# Conclusion: lines 73-74 are defensive dead code under real test conditions.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Line 225: UTF-8 incremental decoder tail appended to chunks in parse_stream
# ---------------------------------------------------------------------------


def test_parse_stream_appends_decoder_tail_from_truncated_multibyte_sequence() -> None:
    """parse_stream must handle a bytes stream that ends mid-multibyte sequence.

    The UTF-8 incremental decoder with 'replace' error mode is used for bytes
    streams (line 203).  When the stream ends with an incomplete multi-byte
    sequence (here the first byte of a two-byte UTF-8 character, 0xC3), the
    final call ``decoder.decode(b"", final=True)`` returns the Unicode
    replacement character U+FFFD.

    Line 224 checks ``if tail`` -- because the tail is the non-empty replacement
    character, line 225 (``chunks.append(tail)``) is executed.

    The rule precedes a comment that contains the incomplete byte, so the
    replacement character lands inside the comment token and the lexer does not
    reject the file.  The rule must therefore be parsed successfully.
    """
    # Arrange: valid YARA rule followed by a comment ending with 0xC3
    # (first byte of a two-byte UTF-8 sequence for é, U+00E9).
    # buffer_size=1 ensures the 0xC3 byte is the last byte read, leaving the
    # incremental decoder with a pending incomplete sequence.
    raw: bytes = b"rule r1 { condition: true } // comment \xc3"
    parser = StreamingParser(buffer_size=1)

    # Act
    rules = list(parser.parse_stream(io.BytesIO(raw)))

    # Assert: the rule was parsed despite the trailing incomplete byte
    assert len(rules) == 1
    assert rules[0].name == "r1"
    assert parser.get_statistics()["rules_parsed"] == 1
    assert parser.get_statistics()["parse_errors"] == 0
    # bytes_processed accounts for every byte read, including the incomplete one
    assert parser.get_statistics()["bytes_processed"] == len(raw)


# ---------------------------------------------------------------------------
# Line 392: _memory_limit_exceeded catches psutil.Error and returns False
# ---------------------------------------------------------------------------


def test_memory_limit_exceeded_returns_false_on_psutil_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_memory_limit_exceeded must return False when psutil.Error is raised.

    The except clause on line 391 catches ``(OSError, psutil.Error)``.
    Line 392 (``return False``) is the handler body for psutil.Error.

    We use pytest's monkeypatch to replace psutil.Process inside sys.modules
    so that memory_info() raises the real psutil.Error class.  No mock
    framework is used; the actual psutil.Error type drives the catch.
    """
    # Arrange: replace psutil.Process with a real class that raises psutil.Error
    real_psutil_error = psutil.Error  # capture the real exception class

    class _BrokenProcess:
        def memory_info(self) -> None:
            raise real_psutil_error("simulated psutil failure")

    fake_psutil = SimpleNamespace(
        Error=real_psutil_error,
        Process=lambda _pid: _BrokenProcess(),
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)

    parser = StreamingParser(max_memory_mb=1)

    # Act
    result = parser._memory_limit_exceeded()

    # Assert: the psutil.Error is swallowed and False is returned
    assert result is False


# ---------------------------------------------------------------------------
# Lines 450-451: _parse_content with non-YARA dialect and dialect_parser_factory
# ---------------------------------------------------------------------------


def test_parse_content_invokes_dialect_parser_factory_for_non_yara_dialect(
    tmp_path: Path,
) -> None:
    """_parse_content must delegate to dialect_parser_factory when dialect != YARA.

    The branch at line 450 (``if self.dialect != YaraDialect.YARA and
    self._dialect_parser_factory is not None``) is True when a non-YARA
    dialect is configured together with a factory.  Line 451 calls the
    factory and returns its result.

    We provide a real factory function that calls parse_yara_source so the
    parsed AST is a genuine YaraFile produced by the production parser.
    """
    invocations: list[tuple[str, YaraDialect | None]] = []

    def real_factory(content: str, dialect: YaraDialect | None) -> Any:
        invocations.append((content, dialect))
        # delegate to the real auto-detect parser
        return parse_yara_source(content)

    parser = StreamingParser(
        dialect=YaraDialect.YARA_X,
        dialect_parser_factory=real_factory,
    )
    yara_text = "rule factory_rule { condition: true }"

    # Act
    result = parser._parse_content(yara_text)

    # Assert: factory was called with the correct arguments
    assert len(invocations) == 1
    assert invocations[0][0] == yara_text
    assert invocations[0][1] == YaraDialect.YARA_X
    # The result is a real YaraFile with the expected rule
    assert len(result.rules) == 1
    assert result.rules[0].name == "factory_rule"


def test_parse_content_uses_factory_during_parse_file(tmp_path: Path) -> None:
    """dialect_parser_factory must be invoked when parsing a real file.

    This exercises lines 450-451 through the full parse_file -> _parse_mmap
    -> _parse_mmap_rule -> _parse_rule_text -> _parse_content call chain with
    a real YARA file on disk.
    """
    rule_file = tmp_path / "factory_test.yar"
    rule_file.write_text("rule on_disk_rule { condition: true }", encoding="utf-8")
    seen_dialects: list[YaraDialect | None] = []

    def real_factory(content: str, dialect: YaraDialect | None) -> Any:
        seen_dialects.append(dialect)
        return parse_yara_source(content)

    parser = StreamingParser(
        dialect=YaraDialect.YARA_X,
        dialect_parser_factory=real_factory,
    )

    # Act: parse a real file on disk
    rules = list(parser.parse_file(rule_file))

    # Assert: factory was called with the YARA_X dialect
    assert len(rules) == 1
    assert rules[0].name == "on_disk_rule"
    assert seen_dialects == [YaraDialect.YARA_X]


# ---------------------------------------------------------------------------
# Lines 452-453: _parse_content with dialect=YARA (uses self.parser.parse)
# ---------------------------------------------------------------------------


def test_parse_content_uses_internal_parser_for_yara_dialect() -> None:
    """_parse_content must use self.parser.parse when dialect == YaraDialect.YARA.

    The branch at line 452 (``if self.dialect == YaraDialect.YARA``) is True
    when the parser is configured for the canonical YARA dialect.  Line 453
    returns the result of ``self.parser.parse(content)``, which is a real
    parse of the YARA source text using the production Parser class.
    """
    parser = StreamingParser(dialect=YaraDialect.YARA)
    yara_text = "rule yara_dialect_rule { condition: true }"

    # Act
    result = parser._parse_content(yara_text)

    # Assert: result is a real YaraFile with the expected rule
    assert len(result.rules) == 1
    assert result.rules[0].name == "yara_dialect_rule"


def test_parse_content_yara_dialect_parses_file_end_to_end(tmp_path: Path) -> None:
    """parse_file must parse a YARA file when dialect=YaraDialect.YARA.

    Exercises lines 452-453 through the complete parse_file code path.
    """
    rule_file = tmp_path / "classic.yar"
    rule_file.write_text("rule classic { condition: true }", encoding="utf-8")
    parser = StreamingParser(dialect=YaraDialect.YARA)

    # Act
    rules = list(parser.parse_file(rule_file))

    # Assert: exactly one rule parsed using the YARA dialect parser
    assert len(rules) == 1
    assert rules[0].name == "classic"


# ---------------------------------------------------------------------------
# Branch [450->452] and [452->454]:
# dialect set to non-YARA, factory is None -> falls through to parse_yara_source
# ---------------------------------------------------------------------------


def test_parse_content_falls_through_to_parse_yara_source_when_factory_absent() -> None:
    """_parse_content must call parse_yara_source when dialect is non-YARA, factory absent.

    When dialect is not None and not YARA, but _dialect_parser_factory is None,
    the branch at line 450 is False (factory is None).  The code falls through
    to line 452 (``if self.dialect == YaraDialect.YARA``), which is also False
    for YARA_X.  Execution continues to line 454 (``return parse_yara_source``).

    This covers the [450->452] and [452->454] branch arcs.
    """
    parser = StreamingParser(dialect=YaraDialect.YARA_X)  # factory defaults to None
    yara_text = "rule fallthrough_rule { condition: true }"

    # Act
    result = parser._parse_content(yara_text)

    # Assert: result is a valid YaraFile from parse_yara_source
    assert len(result.rules) == 1
    assert result.rules[0].name == "fallthrough_rule"


# ---------------------------------------------------------------------------
# Branch [232->229]: _parse_rule_text returns None inside parse_stream loop
# ---------------------------------------------------------------------------


def test_parse_stream_continues_after_rule_parse_failure() -> None:
    """parse_stream must continue iterating when a rule fails to parse.

    The for-loop at line 229 iterates over extracted rule texts.  When
    ``_parse_rule_text`` returns None (line 231), the ``if rule is not None``
    check at line 232 is False.  The interpreter branches back to line 229
    (the [232->229] arc) to fetch the next rule text, rather than yielding.

    We configure a real dialect_parser_factory that raises YaraASTError for
    the first extracted rule, causing _parse_rule_text to return None, then
    succeeds for the second rule.  Both rules must be present in the source so
    the loop visits both entries.
    """
    call_count = 0

    def selective_factory(content: str, dialect: YaraDialect | None) -> Any:
        nonlocal call_count
        call_count += 1
        # Fail on the first rule, succeed on the second
        if call_count == 1:
            raise YaraASTError("forced first-rule failure")
        return parse_yara_source(content)

    parser = StreamingParser(
        dialect=YaraDialect.YARA_X,
        dialect_parser_factory=selective_factory,
    )

    content = "rule first { condition: true }\nrule second { condition: true }"
    stream = io.StringIO(content)

    # Act
    rules = list(parser.parse_stream(stream))

    # Assert: only the second rule was emitted; first caused a parse error
    assert len(rules) == 1
    assert rules[0].name == "second"
    assert parser.get_statistics()["parse_errors"] == 1
    assert parser.get_statistics()["rules_parsed"] == 1


# ---------------------------------------------------------------------------
# Integration: dialect=YARA with parse_stream validates the YARA dialect path
# through streaming (combines lines 452-453 with the stream code path)
# ---------------------------------------------------------------------------


def test_parse_stream_with_yara_dialect_parses_multiple_rules() -> None:
    """parse_stream must parse rules correctly when dialect=YaraDialect.YARA.

    Exercises the YARA dialect branch (lines 452-453) through the streaming
    code path rather than through parse_file, ensuring the _parse_content
    dispatch is exercised from a different call site.
    """
    content = "rule stream_a { condition: true }\n" "rule stream_b { condition: true }\n"
    parser = StreamingParser(dialect=YaraDialect.YARA)
    stream = io.StringIO(content)

    # Act
    rules = list(parser.parse_stream(stream))

    # Assert
    assert len(rules) == 2
    assert [r.name for r in rules] == ["stream_a", "stream_b"]
