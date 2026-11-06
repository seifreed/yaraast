"""Opt-in, structured logging for YARA AST applications and the CLI."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
import json
import logging
import os
import re
import sys
from time import gmtime
import traceback
from types import TracebackType
from typing import TextIO

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|(?:(?:access|refresh|id|auth)[_-]?)?token|session[_-]?id|"
    r"jwt|credential|credentials|(?:x-)?api[_-]?key|"
    r"client[_-]?secret|private[_ -]?key|secret|authorization|proxy-authorization|"
    r"cookie|set-cookie)\b[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+\S+")
_AUTH_HEADER = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization)\b[\"']?\s*[:=]\s*)[^\r\n]*"
)
_COOKIE_HEADER = re.compile(r"(?i)(\b(?:cookie|set-cookie)\b[\"']?\s*[:=]\s*)[^\r\n]*")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]+")
_MAX_LOG_TEXT = 8192
_CONTEXT_FIELDS = frozenset({"operation", "request_id", "correlation_id", "trace_id", "span_id"})
_LOG_CONTEXT: ContextVar[dict[str, str] | None] = ContextVar("yaraast_log_context", default=None)


class _ConfiguredStreamHandler(logging.StreamHandler[TextIO]):
    """Stream handler owned by this module so repeated setup can replace it."""


class _SafePyglsFilter(logging.Filter):
    """Keep third-party LSP diagnostics useful without logging protocol payloads."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name != "pygls" and not record.name.startswith("pygls."):
            return True
        if record.msg == "LSP framework event" and getattr(record, "event_name", None):
            return True
        if record.levelno < logging.WARNING:
            return False
        exception = record.exc_info[1] if record.exc_info else None
        args = record.args if isinstance(record.args, tuple) else ()
        record.event_name = (
            "lsp.framework.failed" if record.levelno >= logging.ERROR else "lsp.framework.warning"
        )
        record.operation = record.funcName
        if (record.msg == "Failed to handle request %s %s %s" and len(args) == 3) or (
            record.msg == "Failed to handle request %r, unknown method %r" and len(args) == 2
        ):
            record.operation = _safe_text(str(args[1]))[:128]
            if isinstance(args[0], (int, str)):
                record.request_id = _safe_text(str(args[0]))[:128]
        elif record.msg == 'Exception occurred for message "%s"' and len(args) == 1:
            if isinstance(args[0], (int, str)):
                record.request_id = _safe_text(str(args[0]))[:128]
        elif record.msg == "Failed to handle notification %r: %s" and len(args) == 2:
            record.operation = _safe_text(str(args[0]))[:128]
        if exception is not None:
            record.error_type = type(exception).__name__
        record.msg = "LSP framework event"
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def install_pygls_log_filter() -> None:
    """Sanitize pygls records before host handlers or last-resort stderr can see them."""
    for name, logger in logging.getLogger().manager.loggerDict.items():
        if (
            (name == "pygls" or name.startswith("pygls."))
            and isinstance(logger, logging.Logger)
            and not any(isinstance(item, _SafePyglsFilter) for item in logger.filters)
        ):
            logger.addFilter(_SafePyglsFilter())


def _safe_text(value: str) -> str:
    if len(value) > _MAX_LOG_TEXT:
        return "[REDACTED: log value exceeded size limit]"
    value = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", value)
    value = _AUTH_HEADER.sub(r"\1[REDACTED]", value)
    value = _COOKIE_HEADER.sub(r"\1[REDACTED]", value)
    value = _BEARER_TOKEN.sub("Bearer [REDACTED]", value)
    value = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    value = _CONTROL_CHARACTERS.sub(" ", value)
    return value if len(value) <= _MAX_LOG_TEXT else "[REDACTED: log value exceeded size limit]"


def safe_traceback_frames(trace: TracebackType | None) -> str:
    if trace is None:
        return ""
    return "".join(
        f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}\n'
        for frame in traceback.extract_tb(trace)
    )


def _safe_context(values: dict[str, str]) -> dict[str, str]:
    return {key: _safe_text(value)[:128] for key, value in values.items() if value}


@contextmanager
def log_context(**fields: str) -> Iterator[None]:
    """Bind operation or correlation fields to the current thread/async context."""
    invalid = fields.keys() - _CONTEXT_FIELDS
    if invalid:
        raise ValueError(f"Unsupported log context fields: {', '.join(sorted(invalid))}")
    if any(not isinstance(value, str) for value in fields.values()):
        raise TypeError("Log context values must be strings")
    token = _LOG_CONTEXT.set(_safe_context((_LOG_CONTEXT.get() or {}) | fields))
    try:
        yield
    finally:
        _LOG_CONTEXT.reset(token)


class JsonLogFormatter(logging.Formatter):
    """Render allow-listed fields as one safe JSON object per event."""

    def format(self, record: logging.LogRecord) -> str:
        message = _safe_text(record.getMessage())
        event: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "message": message,
            "service": "yaraast",
            "component": record.name,
        }
        environment = os.getenv("YARAAST_ENV")
        if environment:
            event["environment"] = _safe_text(environment)[:128]
        event.update(_LOG_CONTEXT.get() or {})
        for field in (
            "operation",
            "request_id",
            "event_name",
            "outcome",
            "duration_ms",
            "error_code",
            "error_type",
            "stack_trace",
        ):
            value = getattr(record, field, None)
            if value is not None:
                event[field] = value if isinstance(value, (int, float)) else _safe_text(str(value))
        if record.name.startswith("yaraast.lsp"):
            event.setdefault("event_name", "lsp.operation.failed")
            event.setdefault("operation", record.funcName)
        if record.exc_info:
            exception = record.exc_info[1]
            if exception is not None:
                event["error_type"] = type(exception).__name__
            event["stack_trace"] = safe_traceback_frames(record.exc_info[2])
        return json.dumps(event, ensure_ascii=False, separators=(",", ":"))


class SafeTextFormatter(logging.Formatter):
    """Keep human-readable logs while neutralizing control characters and secrets."""

    def format(self, record: logging.LogRecord) -> str:
        error_type = getattr(record, "error_type", None)
        stack_trace = getattr(record, "stack_trace", None)
        if record.exc_info:
            error_type = type(record.exc_info[1]).__name__
            stack_trace = safe_traceback_frames(record.exc_info[2])
        if error_type or stack_trace:
            exception_info = record.exc_info
            exception_text = record.exc_text
            record.exc_info = None
            record.exc_text = None
            try:
                message = super().format(record)
            finally:
                record.exc_info = exception_info
                record.exc_text = exception_text
        else:
            message = super().format(record)
        if error_type:
            message = f"{message} error_type={_safe_text(str(error_type))}"
        if stack_trace:
            message = f"{message}\n{_safe_text(str(stack_trace))}"
        return _safe_text(message)


def configure_logging(
    level: str = "WARNING", log_format: str = "text", *, stream: TextIO | None = None
) -> None:
    """Configure YARA AST logging without changing the host application's root logger."""
    numeric_level = logging.getLevelName(level.upper())
    if not isinstance(numeric_level, int):
        raise ValueError(f"Unknown log level: {level}")
    if log_format not in {"text", "json"}:
        raise ValueError(f"Unknown log format: {log_format}")

    loggers = (logging.getLogger("yaraast"), logging.getLogger("pygls"))
    existing_handlers: set[logging.Handler] = set()
    for logger in loggers:
        for existing in tuple(logger.handlers):
            if isinstance(existing, _ConfiguredStreamHandler):
                logger.removeHandler(existing)
                existing_handlers.add(existing)
    for existing in existing_handlers:
        existing.close()
    handler = _ConfiguredStreamHandler(stream if stream is not None else sys.stderr)
    handler.addFilter(_SafePyglsFilter())
    formatter: logging.Formatter = JsonLogFormatter()
    if log_format == "text":
        formatter = SafeTextFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%SZ"
        )
        formatter.converter = gmtime
    handler.setFormatter(formatter)
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(numeric_level)
        logger.propagate = False
