from __future__ import annotations

import io
import mmap
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.performance.streaming_parser import StreamingParser
from yaraast.performance.validation import validate_file_path_sequence


def test_streaming_parser_bytes_stream_remaining_buffer_and_reset(tmp_path: Path) -> None:
    parser = StreamingParser(buffer_size=8)

    raw = b"rule r1 {\n condition:\n true\n}"  # no trailing newline
    rules = list(parser.parse_stream(io.BytesIO(raw)))
    assert len(rules) == 1

    parser.reset_statistics()
    stats = parser.get_statistics()
    assert stats["rules_parsed"] == 0
    assert stats["bytes_processed"] == 0
    assert stats["parse_errors"] == 0
    assert stats["files_processed"] == 0
    assert stats["files_successful"] == 0
    assert stats["total_parse_time"] == 0

    # parse_rules_from_file exception path
    missing = tmp_path / "missing.yar"
    results = list(parser.parse_rules_from_file(missing))
    assert len(results) == 1
    assert results[0].status.name == "ERROR"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"enable_gc": "true"}, "enable_gc must be a boolean"),
        ({"progress_callback": "bad"}, "progress_callback must be callable"),
        ({"dialect_parser_factory": "bad"}, "dialect_parser_factory must be callable"),
    ],
)
def test_streaming_parser_rejects_invalid_constructor_options(
    kwargs: dict[str, Any], message: str
) -> None:
    with pytest.raises(TypeError, match=message):
        StreamingParser(**kwargs)


def test_streaming_parser_parse_file_rejects_non_callable_callback(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.yar"
    empty_file.write_text("", encoding="utf-8")

    with pytest.raises(TypeError, match="callback must be callable"):
        list(StreamingParser().parse_file(empty_file, callback=cast(Any, "bad")))


def test_streaming_parser_parse_stream_rejects_non_callable_callback() -> None:
    with pytest.raises(TypeError, match="callback must be callable"):
        list(StreamingParser().parse_stream(io.StringIO(""), callback=cast(Any, "bad")))


@pytest.mark.parametrize("stream", [None, object()])
def test_streaming_parser_parse_stream_rejects_streams_without_read(stream: Any) -> None:
    with pytest.raises(TypeError, match="stream must provide a callable read method"):
        list(StreamingParser().parse_stream(cast(Any, stream)))


def test_streaming_parser_parse_stream_rejects_non_text_chunks() -> None:
    class BadStream:
        def read(self, _size: int) -> int:
            return 123

    with pytest.raises(TypeError, match=r"stream\.read\(\) must return str or bytes"):
        list(StreamingParser().parse_stream(cast(Any, BadStream())))


def test_streaming_parser_parse_with_progress_rejects_non_callable_callback(
    tmp_path: Path,
) -> None:
    empty_file = tmp_path / "empty.yar"
    empty_file.write_text("", encoding="utf-8")

    with pytest.raises(TypeError, match="progress_callback must be callable"):
        StreamingParser().parse_with_progress(empty_file, cast(Any, None))


@pytest.mark.parametrize("file_path", ["", "   ", "\t"])
def test_streaming_parser_parse_with_progress_rejects_empty_file_path(
    file_path: str,
) -> None:
    with pytest.raises(ValueError, match="file_path must not be empty"):
        StreamingParser().parse_with_progress(file_path, lambda _processed, _total: None)


def test_streaming_parser_parse_with_progress_rejects_directory_path(tmp_path: Path) -> None:
    with pytest.raises(IsADirectoryError, match="file_path must not be a directory"):
        StreamingParser().parse_with_progress(tmp_path, lambda _processed, _total: None)


def test_streaming_parser_emits_falsy_present_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    class FalsyRule(Rule):
        def __bool__(self) -> bool:
            return False

    rule = FalsyRule(name="falsy", condition=BooleanLiteral(True))
    parser = StreamingParser(buffer_size=8)
    callbacks: list[Rule] = []
    monkeypatch.setattr(parser, "_parse_rule_text", lambda _rule_text: rule)

    rules = list(
        parser.parse_stream(io.StringIO("rule falsy { condition: true }"), callbacks.append)
    )

    assert rules == [rule]
    assert callbacks == [rule]
    assert parser.get_statistics()["rules_parsed"] == 1

    mmap_callbacks: list[Rule] = []
    mmap_rules = list(
        parser._parse_mmap_rule("rule falsy { condition: true }", 32, mmap_callbacks.append)
    )

    assert mmap_rules == [rule]
    assert mmap_callbacks == [rule]


def test_streaming_parser_parse_stream_ignores_braces_inside_strings() -> None:
    parser = StreamingParser(buffer_size=8)
    text = """
rule brace_string {
  strings:
    $a = "}"
  condition:
    $a
}
rule second {
  condition:
    true
}
"""

    rules = list(parser.parse_stream(io.StringIO(text)))

    assert [rule.name for rule in rules] == ["brace_string", "second"]
    assert parser.get_statistics()["parse_errors"] == 0


def test_streaming_parser_progress_cancel_and_memory_paths(tmp_path: Path) -> None:
    p1 = tmp_path / "a.yar"
    p2 = tmp_path / "b.yar"
    p1.write_text("rule a { condition: true }", encoding="utf-8")
    p2.write_text("rule b { condition: true }", encoding="utf-8")

    progress_calls: list[tuple[int, int, str]] = []
    parser = StreamingParser(
        progress_callback=lambda i, total, path: progress_calls.append((i, total, path))
    )
    rows = list(parser.parse_files([p1, p2]))
    assert len(rows) == 2
    assert progress_calls

    # cancel path for parse_files
    parser2 = StreamingParser()
    parser2.cancel()
    assert list(parser2.parse_files([p1, p2])) == []

    # _memory_limit_exceeded true path with a tiny threshold (current RSS > 1 MB)
    parser3 = StreamingParser(max_memory_mb=1)
    assert parser3._memory_limit_exceeded() is True
    parser3._maybe_collect_garbage()


def test_streaming_parser_memory_limit_propagates_internal_psutil_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = StreamingParser(max_memory_mb=1)

    class BrokenProcess:
        def memory_info(self) -> object:
            raise AttributeError("memory info unavailable")

    fake_psutil = SimpleNamespace(
        Error=RuntimeError,
        Process=lambda _pid: BrokenProcess(),
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)

    with pytest.raises(AttributeError, match="memory info unavailable"):
        parser._memory_limit_exceeded()


def test_streaming_parser_parse_files_supports_yarax(tmp_path: Path) -> None:
    path = tmp_path / "yarax.yar"
    path.write_text(
        "rule x { condition: with xs = [1]: match xs { _ => true } }",
        encoding="utf-8",
    )
    parser = StreamingParser()

    rows = list(parser.parse_files([path]))

    assert len(rows) == 1
    assert rows[0].status.name == "SUCCESS"
    assert rows[0].ast is not None
    assert rows[0].ast.rules[0].condition.__class__.__name__ == "WithStatement"


def test_streaming_parser_rejects_invalid_utf8_file_inputs(tmp_path: Path) -> None:
    path = tmp_path / "bad_utf8.yar"
    path.write_bytes(b"\xff")
    parser = StreamingParser()

    file_results = list(parser.parse_files([path]))
    rule_results = list(parser.parse_rules_from_file(path))

    assert len(file_results) == 1
    assert file_results[0].status.name == "ERROR"
    assert file_results[0].error == "YARA file must contain valid UTF-8 text"
    assert len(rule_results) == 1
    assert rule_results[0].status.name == "ERROR"
    assert rule_results[0].error == "YARA file must contain valid UTF-8 text"


def test_streaming_parser_rejects_single_string_file_paths(tmp_path: Path) -> None:
    path = tmp_path / "single.yar"
    path.write_text("rule single { condition: true }", encoding="utf-8")
    parser = StreamingParser()

    with pytest.raises(TypeError, match="file_paths must be a sequence of paths"):
        list(parser.parse_files(cast(Any, str(path))))


@pytest.mark.parametrize("path", ["", "   ", "\t"])
def test_validate_file_path_sequence_rejects_empty_entries(path: str) -> None:
    with pytest.raises(ValueError, match="file_paths must not contain empty paths"):
        validate_file_path_sequence([path])


@pytest.mark.parametrize("path", ["", "   ", "\t"])
def test_streaming_parser_parse_files_rejects_empty_file_path_entries(path: str) -> None:
    with pytest.raises(ValueError, match="file_paths must not contain empty paths"):
        list(StreamingParser().parse_files(cast(Any, [path])))


def test_streaming_parser_mmap_import_include_and_token_branches(tmp_path: Path) -> None:
    code = """
import "pe"
include "common.yar"
private rule r1 {
  condition:
    true
}
global rule r2 : t1 t2 {
  strings:
    $a = "x"
  condition:
    $a
}
"""
    f = tmp_path / "mm.yar"
    f.write_text(code.strip() + "\n", encoding="utf-8")

    parser = StreamingParser()
    rules = list(parser.parse_file(f))
    assert len(rules) == 2
    assert [r.name for r in rules] == ["r1", "r2"]


def test_streaming_parser_empty_file_yields_no_rules(tmp_path: Path) -> None:
    path = tmp_path / "empty.yar"
    path.write_text("", encoding="utf-8")

    parser = StreamingParser()

    assert list(parser.parse_file(path)) == []


@pytest.mark.parametrize("file_path", ["", "   ", "\t"])
def test_streaming_parser_parse_file_rejects_empty_path(file_path: str) -> None:
    with pytest.raises(ValueError, match="file_path must not be empty"):
        list(StreamingParser().parse_file(file_path))


def test_streaming_parser_parse_file_rejects_directory_path(tmp_path: Path) -> None:
    with pytest.raises(IsADirectoryError, match="file_path must not be a directory"):
        list(StreamingParser().parse_file(tmp_path))


def test_streaming_parser_chunk_residual_callbacks_and_cancellation(tmp_path: Path) -> None:
    text = """
rule a {
  condition:
    true
}

rule b {
  condition:
    true
}

rule c {
  condition:
    true
}"""
    path = tmp_path / "three.yar"
    path.write_text(text, encoding="utf-8")

    parser = StreamingParser(buffer_size=7)
    chunks = list(parser.parse_file_chunked(path, chunk_size=2))
    assert [len(chunk) for chunk in chunks] == [2, 1]

    callback_names: list[str] = []
    stream_rules = list(
        parser.parse_stream(
            io.StringIO(text), callback=lambda rule: callback_names.append(rule.name)
        )
    )
    assert [r.name for r in stream_rules] == ["a", "b", "c"]
    assert callback_names == ["a", "b", "c"]

    parser2 = StreamingParser()
    parser2.cancel()
    assert list(parser2.parse_rules_from_file(path)) == []


def test_streaming_parser_parse_files_error_memory_except_and_rule_text_failures(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "nope.yar"
    parser = StreamingParser()
    results = list(parser.parse_files([missing]))
    assert len(results) == 1
    assert results[0].status.name == "ERROR"

    with pytest.raises(TypeError, match="max_memory_mb must be an integer"):
        StreamingParser(max_memory_mb=cast(Any, "bad"))

    assert parser._parse_rule_text('import "pe"') is None


def test_streaming_parser_parse_rule_text_propagates_internal_parser_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = StreamingParser()

    def broken_parse_content(_content: str) -> object:
        raise AttributeError("parser state missing")

    monkeypatch.setattr(parser, "_parse_content", broken_parse_content)

    with pytest.raises(AttributeError, match="parser state missing"):
        parser._parse_rule_text("rule ok { condition: true }")


def test_streaming_parser_parse_files_propagates_internal_parser_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "ok.yar"
    path.write_text("rule ok { condition: true }", encoding="utf-8")
    parser = StreamingParser()

    def broken_parse_content(_content: str) -> object:
        raise AttributeError("parser state missing")

    monkeypatch.setattr(parser, "_parse_content", broken_parse_content)

    with pytest.raises(AttributeError, match="parser state missing"):
        list(parser.parse_files([path]))


def test_streaming_parser_parse_rules_from_file_propagates_internal_parser_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "ok.yar"
    path.write_text("rule ok { condition: true }", encoding="utf-8")
    parser = StreamingParser()

    def broken_parse_rule_text(_rule_text: str) -> object:
        raise AttributeError("parser state missing")

    monkeypatch.setattr(parser, "_parse_rule_text", broken_parse_rule_text)

    with pytest.raises(AttributeError, match="parser state missing"):
        list(parser.parse_rules_from_file(path))


def test_streaming_parser_parse_stream_invalid_tail_and_mmap_invalid_forms(tmp_path: Path) -> None:
    parser = StreamingParser(buffer_size=8)
    invalid_tail = "rule tail {\n  condition:\n    true"
    assert list(parser.parse_stream(io.StringIO(invalid_tail))) == []
    assert parser.get_statistics()["parse_errors"] >= 1

    invalid_cases = [
        "private\n",
        "rule { condition: true }\n",
        "rule missing_name\n",
        'import "pe"\n',
        "import\n",
        "rule tagged : tag\n",
    ]
    for idx, content in enumerate(invalid_cases):
        path = tmp_path / f"invalid_{idx}.yar"
        path.write_text(content, encoding="utf-8")
        with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            assert list(parser._parse_mmap(mm)) == []


def test_streaming_parser_parse_rules_from_file_success_progress_recursive_and_estimate(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)

    file1 = root / "one.yar"
    file2 = nested / "two.yar"
    file1.write_text("rule one { condition: true }", encoding="utf-8")
    file2.write_text("rule two { condition: true }", encoding="utf-8")

    parser = StreamingParser(buffer_size=4)
    results = list(parser.parse_rules_from_file(file1))
    assert len(results) == 1
    assert results[0].status.name == "SUCCESS"
    assert results[0].rule_name == "one"
    assert results[0].rule_count == 1
    assert results[0].ast is not None

    progress_calls: list[tuple[int, int]] = []
    rules = parser.parse_with_progress(
        file1,
        lambda processed, total: progress_calls.append((processed, total)),
    )
    assert [rule.name for rule in rules] == ["one"]
    assert progress_calls

    recursive_results = list(parser.parse_directory(root, recursive=True))
    assert len(recursive_results) == 2
    assert {r.rule_name for r in recursive_results} == {"one", "two"}

    estimate = parser.estimate_memory_usage(file1)
    assert estimate["file_size_mb"] >= 0
    assert estimate["estimated_ast_mb"] >= estimate["file_size_mb"]
    assert estimate["estimated_peak_mb"] >= estimate["estimated_ast_mb"]

    for file_path in ["", "   ", "\t"]:
        with pytest.raises(ValueError, match="file_path must not be empty"):
            parser.estimate_memory_usage(file_path)

    with pytest.raises(IsADirectoryError, match="file_path must not be a directory"):
        parser.estimate_memory_usage(root)


def test_streaming_parser_parse_directory_accepts_string_path(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }", encoding="utf-8")

    results = list(StreamingParser().parse_directory(str(tmp_path)))

    assert len(results) == 1
    assert results[0].rule_name == "sample"


@pytest.mark.parametrize("dir_path", ["", "   ", "\t"])
def test_streaming_parser_parse_directory_rejects_empty_path(dir_path: str) -> None:
    with pytest.raises(ValueError, match="dir_path must not be empty"):
        list(StreamingParser().parse_directory(dir_path))


def test_streaming_parser_parse_directory_rejects_file_path(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }", encoding="utf-8")

    with pytest.raises(NotADirectoryError, match="dir_path must be a directory"):
        list(StreamingParser().parse_directory(rule_file))


@pytest.mark.parametrize("dir_path", [None, 123, object()])
def test_streaming_parser_parse_directory_rejects_invalid_path_types(dir_path: Any) -> None:
    with pytest.raises(TypeError, match="dir_path must be a string or path-like object"):
        list(StreamingParser().parse_directory(cast(Any, dir_path)))


@pytest.mark.parametrize("recursive", [None, 1, "true", object()])
def test_streaming_parser_parse_directory_rejects_invalid_recursive_types(
    tmp_path: Path, recursive: Any
) -> None:
    with pytest.raises(TypeError, match="recursive must be a boolean"):
        list(StreamingParser().parse_directory(tmp_path, recursive=cast(bool, recursive)))


def test_streaming_parser_mmap_nested_brace_callback_and_invalid_parse_object(
    tmp_path: Path,
) -> None:
    nested_brace = "rule weird { condition: { true } }"
    path = tmp_path / "nested_brace.yar"
    path.write_text(nested_brace, encoding="utf-8")

    parser = StreamingParser()
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert list(parser._parse_mmap(mm, callback=lambda rule: None)) == []
        assert parser.get_statistics()["parse_errors"] >= 1
