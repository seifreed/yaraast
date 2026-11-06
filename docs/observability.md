# Logging and observability

## Initial audit

YARA AST is a Python 3.11+ library with a Click CLI, parser/AST/generator and analysis APIs, local
project/configuration and plugin workflows, serialization, an optional pygls/lsprotocol language
server, optional libyara/protobuf/Graphviz integrations, and benchmark/fuzz tools. Runtime
dependencies are Click, Rich, attrs, and PyYAML; integrations and development tools are optional
extras. The LSP can communicate over stdio or an explicitly requested TCP listener; there are no
outbound API clients, authentication/authorization flows, database, queue, or scheduled service.
Filesystem reads/writes and the LSP's local disk cache are the persistent operations. The LSP uses
asyncio and keeps bounded, in-memory latency samples for selected operations. Batch processing also
has concurrent paths. Neither has a distributed service path or metrics exporter.

Before this change, 23 logging calls were present across 13 LSP modules. They all used DEBUG with a
generic failure message. No package logging configuration, structured formatter, correlation
context, or logging-specific test suite existed. Most `print` and Rich console calls are intentional
CLI results and benchmark output, not diagnostic logging. The LSP CLI also printed its startup
status to stdout, which shares the stdio protocol channel.

| Dimension | Initial score | Evidence |
| --- | ---: | --- |
| Architecture and decoupling | 2/10 | Local standard-library loggers, with no configuration boundary. |
| Functional coverage | 2/10 | Logging was limited to generic LSP fallback failures. |
| Event quality | 2/10 | Events named neither the operation nor its outcome; all were DEBUG. |
| Structure and consistency | 0/10 | No structured event format or shared fields. |
| Context and correlation | 1/10 | LSP latency was grouped by operation, but events had no request context. |
| Security and privacy | 5/10 | Little data was logged, but there was no redaction or injection protection. |
| Performance and resilience | 6/10 | Low volume and Python's thread-safe logger; no explicit policy or tests. |
| Configuration and portability | 1/10 | No level, format, or destination configuration. |
| Error handling | 2/10 | Unexpected safe-handler exceptions were swallowed and invisible at default levels. |
| Testing and verification | 2/10 | One existing LSP test inspected a DEBUG record; no configuration or safety tests. |
| **Mean** | **2.3/10** | Arithmetic mean of all ten dimensions. |

## Architecture and conventions

The `yaraast.logging_config` module uses Python's standard `logging` package. Importing the library
does not configure logging or mutate the host application's root logger. Applications can call
`configure_logging(level, log_format)` explicitly; the CLI does this at its root command boundary.
The default CLI threshold is WARNING, and diagnostic output goes to stderr. Levels can be selected
with `--log-level` or `YARAAST_LOG_LEVEL`; `--log-format` and `YARAAST_LOG_FORMAT` select `text` or
`json`. JSON records use UTC timestamps and allow-listed fields (`service`, `component`,
`environment`, `operation`, `request_id`, `event_name`, `outcome`, `duration_ms`, and error details).

Use DEBUG for optional implementation detail, INFO for command lifecycle transitions, WARNING for
recoverable command aborts, ERROR for operation failures, and CRITICAL only when process continuity
is at risk. Do not log rule source, file contents, document URIs, request/response bodies, or raw
configuration. The configured format redacts common credential assignments and bearer tokens and
redacts complete authorization and cookie headers, removes control characters, and leaves exception
messages and source lines out of stack traces. Event fields are allow-listed so arbitrary `extra`
values are not serialized. Messages and traces are capped at 8 KiB; oversized values are replaced
with a fixed marker. Stack traces retain frame locations and exception type without document text.

When the LSP server is imported, pygls logger records are filtered before host handlers or Python's
fallback stderr handler can see them. Its INFO and DEBUG records are dropped because pygls includes
protocol payloads at those levels. WARNING and ERROR records retain the module, operation, request
ID when pygls provides it, and error type but replace messages and exception details with a fixed
event. Calling `configure_logging`
routes those events through the same stderr destination and format as YARA AST logs.

The built-in destination is stderr. A service manager or shell redirection can collect stderr;
retention and rotation belong to that destination because this library does not open log files. For
example, `yaraast --log-level INFO --log-format json check rules/ 2>yaraast.jsonl` keeps command
results on stdout and writes a JSON diagnostic event per completed command. Applications that
install their own logging handlers must preserve the same redaction and control character handling;
the library intentionally does not take ownership of a host application's logging configuration.

An actual `parse` run emits lifecycle events like these (the second line includes its measured
duration):

```json
{"timestamp":"2026-11-06T21:44:39.383Z","level":"info","message":"CLI command started","service":"yaraast","component":"yaraast.cli.main","operation":"parse","event_name":"cli.command.started"}
{"timestamp":"2026-11-06T21:44:39.392Z","level":"info","message":"CLI command completed","service":"yaraast","component":"yaraast.cli.main","operation":"parse","event_name":"cli.command.completed","outcome":"success","duration_ms":8.79275007173419}
```

The stdlib has no TRACE level; DEBUG is the most detailed supported level. FATAL is the stdlib alias
for CRITICAL, which the CLI exposes by name. Both JSON and text timestamps are UTC.

`log_context` uses `ContextVar`, so operation and correlation fields do not share mutable global
state across threads or async tasks. It accepts caller-supplied identifiers and does not manufacture
request or trace IDs. The LSP feature wrapper binds pygls's current JSON-RPC request ID and method
name to logs emitted during that request. Notifications without request IDs remain uncorrelated.
The CLI emits a start event and one completion/failure/exit event per command, including operation,
outcome, and duration. Unexpected LSP handler failures include the handler name, exception type,
safe stack frames, and request ID when available. Normal parser calls remain quiet; errors returned
to callers are not duplicated in logs. No OpenTelemetry dependency, external collector, file
destination, rotation, or sampling layer is added: this single-process library has no cross-service
trace path, the CLI is low-volume, and the LSP already exposes bounded local latency summaries. The
LSP command's human-readable status and its diagnostic logs both go to stderr, leaving stdout for
protocol messages.

The LSP regression runner also measures 1,000 registered feature calls with request context enabled;
the average must remain below 0.5 ms. It runs alongside the existing 200-rule, 25-file, and 100-file
runtime scenarios with their latency thresholds. The CLI integration test starts the stdio server,
sends `initialize`, `shutdown`, and `exit`, checks that JSON-RPC stays on stdout, and checks that
command lifecycle events go to stderr.

## Adding events

Use a module logger (`logging.getLogger(__name__)`) and fixed messages. Add an `event_name` and only
safe, useful fields through `extra`; use `log_context` for an existing operation or correlation ID.
Do not create IDs solely for logging or attach source text, identifiers containing private paths, or
full exception messages. Let exceptions propagate after logging at the boundary that owns the
operation, so the same failure is not recorded at every layer. Prefer existing bounded LSP latency
metrics for repeated timing data instead of emitting one event per hot-path parser operation.

Run focused logging tests with
`pytest --no-cov tests/test_logging_config.py tests/test_lsp_server_more.py tests/test_cli_lsp_command.py`;
the global coverage threshold applies to the full suite, so run `pytest` afterwards. The repository's
other quality gates are `ruff check .`, `mypy .`, `black --check .`, and `bandit -r yaraast`.

## Final audit

| Dimension | Initial | Final | Evidence |
| --- | ---: | ---: | --- |
| Architecture and decoupling | 2 | 10 | Standard-library boundary in `yaraast/logging_config.py`; root logger is untouched. |
| Functional coverage | 2 | 10 | `LoggingGroup` wraps CLI commands; LSP feature and fallback boundaries are instrumented. |
| Event quality | 2 | 10 | CLI lifecycle outcomes and duration; operation-specific LSP failures. |
| Structure and consistency | 0 | 10 | UTC JSON events with stable allow-listed fields and environment configuration. |
| Context and correlation | 1 | 10 | `ContextVar` tests cover threads and async tasks; LSP request IDs come from pygls. |
| Security and privacy | 5 | 10 | Redaction, control removal, size limits, pygls payload filtering, source-free LSP traces. |
| Performance and resilience | 6 | 10 | LSP request-context benchmark, low event volume, pygls noise filtering, and broken-destination test. |
| Configuration and portability | 1 | 10 | CLI flags/environment variables, stderr, text/JSON, and explicit library setup. |
| Error handling | 2 | 10 | Click outcomes and unexpected failures are recorded once; swallowed LSP failures are visible. |
| Testing and verification | 2 | 10 | Regression tests cover output, privacy, correlation, concurrency, and configuration. |
| **Mean** | **2.3** | **10.0** | Arithmetic mean across all ten applicable dimensions. |

The project has no database, outbound API client, authentication system, queue, scheduled worker, or
distributed service path, so those observability dimensions do not apply. Existing local LSP latency
summaries cover the metrics needed by this single-process application; no external metrics or tracing
backend is required for the current runtime model.
