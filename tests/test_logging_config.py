"""Tests for the opt-in logging configuration and operational events."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
import json
import logging
from pathlib import Path

from click.testing import CliRunner
import pytest

from yaraast.cli.main import cli
from yaraast.logging_config import configure_logging, log_context
from yaraast.lsp.safe_handler import lsp_safe_handler


@pytest.fixture
def log_sink() -> Iterator[tuple[logging.Logger, StringIO]]:
    loggers = (logging.getLogger("yaraast"), logging.getLogger("pygls"))
    original_state = {
        logger: (logger.handlers[:], logger.level, logger.propagate) for logger in loggers
    }
    stream = StringIO()
    configure_logging("DEBUG", "json", stream=stream)
    yield loggers[0], stream
    original_handlers = {
        handler for handlers, _, _ in original_state.values() for handler in handlers
    }
    added_handlers = {
        handler for logger in loggers for handler in logger.handlers
    } - original_handlers
    for logger in loggers:
        for handler in tuple(logger.handlers):
            if handler in added_handlers:
                logger.removeHandler(handler)
    for handler in added_handlers:
        if handler not in original_handlers:
            handler.close()
    for logger, (handlers, level, propagate) in original_state.items():
        for handler in handlers:
            if handler not in logger.handlers:
                logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = propagate


def test_json_events_include_context_and_redact_secrets(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    _, stream = log_sink
    logger = logging.getLogger("yaraast.tests.logging_config")
    with log_context(operation="parse", correlation_id="corr-17"):
        logger.info(
            "Rejected password='two words' token=secret-value Authorization: Bearer bearer-value\n"
            'forged "auth_token":"auth-value" "session_id":"session-value" '
            "Cookie: sid=session-cookie; theme=private-theme\n"
            "Authorization: Basic basic-secret "
            "-----BEGIN PRIVATE KEY-----private-material-----END PRIVATE KEY-----",
            extra={"api_key": "extra-secret"},
        )

    event = json.loads(stream.getvalue())
    assert event["timestamp"].endswith("Z")
    assert event["level"] == "info"
    assert event["service"] == "yaraast"
    assert event["component"] == "yaraast.tests.logging_config"
    assert event["operation"] == "parse"
    assert event["correlation_id"] == "corr-17"
    assert "two words" not in event["message"]
    assert "secret-value" not in event["message"]
    assert "bearer-value" not in event["message"]
    assert "auth-value" not in event["message"]
    assert "session-value" not in event["message"]
    assert "session-cookie" not in event["message"]
    assert "private-theme" not in event["message"]
    assert "basic-secret" not in event["message"]
    assert "private-material" not in event["message"]
    assert "extra-secret" not in stream.getvalue()
    assert "\n" not in event["message"]


def test_log_message_size_is_bounded(log_sink: tuple[logging.Logger, StringIO]) -> None:
    logger, stream = log_sink
    logger.info("%s", "x" * 9000)

    event = json.loads(stream.getvalue())

    assert event["message"] == "[REDACTED: log value exceeded size limit]"


def test_log_context_resets_after_scope(log_sink: tuple[logging.Logger, StringIO]) -> None:
    logger, stream = log_sink
    with log_context(request_id="request-1"):
        logger.info("in scope")
    logger.info("outside scope")

    first, second = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert first["request_id"] == "request-1"
    assert "request_id" not in second


def test_lsp_exception_logs_have_a_structured_operation(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    _, stream = log_sink
    logger = logging.getLogger("yaraast.lsp.sample")
    try:
        raise ValueError("invalid input")
    except ValueError:
        logger.debug("Operation failed", exc_info=True)

    event = json.loads(stream.getvalue())
    assert event["event_name"] == "lsp.operation.failed"
    assert event["operation"] == "test_lsp_exception_logs_have_a_structured_operation"
    assert event["error_type"] == "ValueError"


def test_log_context_is_isolated_between_threads(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    logger, stream = log_sink

    def emit(request_id: str) -> None:
        with log_context(request_id=request_id):
            logger.info("worker completed")

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(emit, ["r1", "r2", "r3", "r4"]))

    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert {event["request_id"] for event in events} == {"r1", "r2", "r3", "r4"}


def test_log_context_is_propagated_between_async_tasks(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    logger, stream = log_sink

    async def emit(request_id: str) -> None:
        with log_context(request_id=request_id):
            await asyncio.sleep(0)
            logger.info("async worker completed")

    async def run() -> None:
        await asyncio.gather(*(emit(request_id) for request_id in ("a1", "a2")))

    asyncio.run(run())

    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert {event["request_id"] for event in events} == {"a1", "a2"}


def test_error_event_keeps_type_and_redacts_traceback(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    logger, stream = log_sink
    try:
        raise RuntimeError("api_key=private-key")
    except RuntimeError:
        logger.exception("Operation failed")

    event = json.loads(stream.getvalue())
    assert event["error_type"] == "RuntimeError"
    assert "stack_trace" in event
    assert "private-key" not in event["stack_trace"]


def test_pygls_protocol_events_do_not_log_request_bodies(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    _, stream = log_sink
    framework_logger = logging.getLogger("pygls.protocol.json_rpc")
    framework_logger.debug("Sending data: %s", {"text": "private debug body"})
    try:
        raise ValueError("private rule text")
    except ValueError:
        framework_logger.exception(
            "Failed to handle request %s %s %s",
            17,
            "textDocument/didOpen",
            {"text": "private rule body"},
        )

    event = json.loads(stream.getvalue())

    assert event["event_name"] == "lsp.framework.failed"
    assert event["operation"] == "textDocument/didOpen"
    assert event["request_id"] == "17"
    assert event["error_type"] == "ValueError"
    assert event["message"] == "LSP framework event"
    assert "private rule" not in stream.getvalue()
    assert "stack_trace" not in event


def test_cli_selects_json_and_records_command_duration(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["--log-level", "INFO", "--log-format", "json", "parse", str(rule_file)],
    )

    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.output.splitlines() if line.startswith("{")]
    assert [event["event_name"] for event in events] == [
        "cli.command.started",
        "cli.command.completed",
    ]
    assert events[-1]["operation"] == "parse"
    assert events[-1]["outcome"] == "success"
    assert events[-1]["duration_ms"] >= 0


def test_cli_records_nonzero_system_exit_as_failure(tmp_path: Path) -> None:
    rule_file = tmp_path / "invalid.yar"
    rule_file.write_text("rule broken {", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["--log-level", "INFO", "--log-format", "json", "parse", str(rule_file)],
    )

    assert result.exit_code == 1
    events = [json.loads(line) for line in result.output.splitlines() if line.startswith("{")]
    assert [event["event_name"] for event in events] == [
        "cli.command.started",
        "cli.command.exited",
    ]
    assert events[-1]["operation"] == "parse"
    assert events[-1]["outcome"] == "error"
    assert events[-1]["error_type"] == "SystemExit"


def test_cli_logging_can_be_configured_with_environment(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["parse", str(rule_file)],
        env={"YARAAST_LOG_LEVEL": "INFO", "YARAAST_LOG_FORMAT": "json"},
    )

    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.output.splitlines() if line.startswith("{")]
    assert [event["event_name"] for event in events] == [
        "cli.command.started",
        "cli.command.completed",
    ]


def test_lsp_safe_handler_logs_swallowed_failure(caplog: pytest.LogCaptureFixture) -> None:
    @lsp_safe_handler(default=[])
    def broken_handler() -> list[object]:
        raise RuntimeError("private rule body")

    with caplog.at_level(logging.ERROR, logger="yaraast.lsp.safe_handler"):
        assert broken_handler() == []

    record = next(record for record in caplog.records if record.name == "yaraast.lsp.safe_handler")
    assert getattr(record, "event_name", None) == "lsp.handler.failed"
    assert record.levelno == logging.ERROR
    assert getattr(record, "error_type", None) == "RuntimeError"
    assert record.exc_info is None
    assert "private rule body" not in caplog.text


def test_lsp_stack_trace_omits_exception_payload(log_sink: tuple[logging.Logger, StringIO]) -> None:
    _, stream = log_sink

    @lsp_safe_handler
    def broken_handler() -> None:
        raise RuntimeError("private rule body")

    broken_handler()
    event = json.loads(stream.getvalue())

    assert event["error_type"] == "RuntimeError"
    assert "stack_trace" in event
    assert "private rule body" not in event["stack_trace"]


def test_lsp_text_stack_trace_omits_exception_payload(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    _, stream = log_sink
    logger = logging.getLogger("yaraast.lsp.sample")
    configure_logging("ERROR", "text", stream=stream)
    try:
        raise RuntimeError("private rule body")
    except RuntimeError:
        logger.exception("LSP handler failed")

    output = stream.getvalue()

    assert "error_type=RuntimeError" in output
    assert "private rule body" not in output
    assert "test_lsp_text_stack_trace_omits_exception_payload" in output


def test_configured_level_filters_lower_priority_events(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    logger, stream = log_sink
    configure_logging("ERROR", "json", stream=stream)
    logger.info("filtered")
    logger.error("visible")

    assert [json.loads(line)["message"] for line in stream.getvalue().splitlines()] == ["visible"]


def test_text_format_uses_utc_timestamp(log_sink: tuple[logging.Logger, StringIO]) -> None:
    logger, stream = log_sink
    configure_logging("INFO", "text", stream=stream)
    record = logging.LogRecord("yaraast.tests", logging.INFO, "", 0, "ready", (), None)
    record.created = 0
    handler = next(
        handler for handler in logger.handlers if getattr(handler, "stream", None) is stream
    )

    handler.handle(record)

    assert stream.getvalue().startswith("1970-01-01T00:00:00Z INFO yaraast.tests ready")


def test_configuration_includes_environment_when_set(
    log_sink: tuple[logging.Logger, StringIO], monkeypatch: pytest.MonkeyPatch
) -> None:
    logger, stream = log_sink
    monkeypatch.setenv("YARAAST_ENV", "staging")
    logger.info("ready")

    assert json.loads(stream.getvalue())["environment"] == "staging"


def test_broken_log_destination_does_not_raise(
    log_sink: tuple[logging.Logger, StringIO], monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenStream(StringIO):
        def write(self, value: str) -> int:
            raise OSError("destination is unavailable")

    logger, _ = log_sink
    configure_logging("ERROR", "json", stream=BrokenStream())
    monkeypatch.setattr(logging, "raiseExceptions", False)

    logger.error("destination failure")


def test_configure_logging_leaves_root_logger_untouched(
    log_sink: tuple[logging.Logger, StringIO],
) -> None:
    _, stream = log_sink
    root = logging.getLogger()
    original_level = root.level
    original_handlers = root.handlers[:]

    configure_logging("INFO", "text", stream=stream)

    assert root.level == original_level
    assert root.handlers == original_handlers
