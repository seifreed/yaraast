# Logging and observability

## Initial audit

YARA AST is a Python 3.11+ library with a Click CLI, parser/AST/generator and analysis APIs, local
project/configuration and plugin workflows, serialization, an optional pygls/lsprotocol language
server, optional libyara/protobuf/Graphviz integrations, and benchmark/fuzz tools. The repository
also contains a TypeScript VS Code extension that launches the LSP over stdio. Runtime dependencies
are Click, Rich, attrs, and PyYAML; integrations and development tools are optional extras. There
are no outbound API clients, authentication/authorization flows, database, queue, or scheduled
service. Filesystem reads/writes and the LSP's local disk cache are the persistent operations. The
LSP uses asyncio and keeps bounded, in-memory latency samples for selected operations. Batch
processing also has concurrent paths. Neither component has a distributed service path or metrics
exporter.

Before this change, 23 logging calls were present across 13 LSP modules. They all used DEBUG with a
generic failure message. The VS Code extension also wrote ad hoc `[info]`/`[error]` text to output
channels, logged raw exception text and serialized runtime settings, and silently ignored runtime
status request failures. No package logging configuration, structured formatter, correlation
context, or logging-specific test suite existed. Most `print` and Rich console calls are intentional
CLI results and benchmark output, not diagnostic logging. The LSP CLI also printed its startup
status to stdout, which shares the stdio protocol channel.

| Dimension | Initial score | Evidence |
| --- | ---: | --- |
| Architecture and decoupling | 2/10 | Python used local loggers and the extension wrote directly to output channels. |
| Functional coverage | 3/10 | Generic LSP fallback failures and a few unstructured extension transitions. |
| Event quality | 2/10 | Python events named neither the operation nor its outcome; all were DEBUG. |
| Structure and consistency | 1/10 | Extension prefixes existed, but no structured format or shared fields. |
| Context and correlation | 1/10 | LSP latency was grouped by operation, but events had no request context. |
| Security and privacy | 3/10 | Extension logs could include exception messages and serialized settings; no redaction. |
| Performance and resilience | 6/10 | Low volume and Python's thread-safe logger; no explicit policy or tests. |
| Configuration and portability | 3/10 | VS Code could enable protocol traces, but application log levels and format were fixed. |
| Error handling | 2/10 | Unexpected safe-handler exceptions were swallowed and invisible at default levels. |
| Testing and verification | 2/10 | One existing LSP test inspected a DEBUG record; no configuration or safety tests. |
| **Mean** | **2.5/10** | Arithmetic mean of all ten dimensions. |

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
with a fixed marker. Stack traces retain frame basenames, line numbers, and function names without
absolute paths, exception messages, or document text.

When the LSP server is imported, pygls logger records are filtered before host handlers or Python's
fallback stderr handler can see them. Its INFO and DEBUG records are dropped because pygls includes
protocol payloads at those levels. WARNING and ERROR records retain the module, operation, request
ID when pygls provides it, and error type but replace messages and exception details with a fixed
event. Calling `configure_logging`
routes those events through the same stderr destination and format as YARA AST logs.

Recoverable LSP feature fallbacks emit `lsp.operation.fallback` at DEBUG with a stable operation,
`outcome=fallback`, exception type, and safe stack frames. Parse failures caused by an incomplete
editor buffer remain DEBUG because they are expected during editing; unexpected handler failures
are ERROR events at the safe-handler boundary.

The built-in destination is stderr. A service manager or shell redirection can collect stderr;
retention and rotation belong to that destination because this library does not open log files. For
example, `yaraast --log-level INFO --log-format json check rules/ 2>yaraast.jsonl` keeps command
results on stdout and writes a JSON diagnostic event per completed command. Applications that
install their own logging handlers must preserve the same redaction and control character handling;
the library intentionally does not take ownership of a host application's logging configuration.

An actual `parse` run emits lifecycle events like these (the second line includes its measured
duration):

```json
{"timestamp":"2026-11-08T07:08:17.102Z","level":"info","message":"CLI command started","service":"yaraast","component":"yaraast.cli.main","operation":"parse","event_name":"cli.command.started"}
{"timestamp":"2026-11-08T07:08:17.111Z","level":"info","message":"CLI command completed","service":"yaraast","component":"yaraast.cli.main","operation":"parse","event_name":"cli.command.completed","outcome":"success","duration_ms":9.210749994963408}
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

## VS Code extension

`vscode-yaraast/src/logging.ts` is the extension's logging boundary. It writes JSON event payloads
to VS Code's native `YARAAST Language Server` `LogOutputChannel`, using normalized fields for `timestamp`,
`level`, `message`, `service`, `component`, `event_name`, `operation`, `outcome`, `duration_ms`,
`error_type`, and `error_code`. It uses the host-provided channel rather than opening files or
requiring a remote collector. If the channel throws, the event is dropped so diagnostics cannot
interrupt the editor.

Activation, deactivation, server start/stop/disable, setting changes, and runtime status failures are
recorded. Commands share a failure boundary that records the operation, outcome, duration, and
exception type, then rethrows the original error. It never writes exception messages, raw settings,
rule text, document contents, or request/response bodies. Dynamic text is redacted for credential
assignments, authorization/cookie headers, bearer values, and private keys; control characters are
removed and text values over 8 KiB are replaced. The extension's event volume is low, so synchronous
Output Channel writes are sufficient; no background buffer or separate file rotation is warranted.

The helper supports VS Code's `trace`, `debug`, `info`, `warn`, and `error` levels, and the channel's
configured log level filters events at the destination. Automatic lifecycle events use `info`,
`warn`, or `error`; no per-document trace events are emitted. The channel follows the editor's log
level; users can change it with `Developer: Set Log Level`. The LSP trace remains a separate VS
Code `YARAAST LSP Trace`
channel controlled by `yaraast.lsp.trace.server`, whose default is `off`. `messages` and especially
`verbose` trace protocol payloads and can include open document text. Keep trace off during normal
use and review trace output before sharing it. The Python request logger uses pygls's existing
JSON-RPC request IDs; the extension does not invent IDs or attempt cross-process trace propagation
for this local stdio child process.

The explicit `YARAAST: Show Server Configuration`, `Show Server Status`, and `Diagnose Server
Environment` commands write human-readable reports to the separate `YARAAST Diagnostics` channel,
not to the structured log. Those reports can contain local interpreter or workspace paths; the
environment report is copied only when the user explicitly requests diagnostics. To inspect normal
events, run `YARAAST: Show Output Channel` and select `YARAAST Language Server` in VS Code's Output
panel.

An event generated through the extension logger has this shape:

```json
{"timestamp":"2026-11-06T22:34:26.425Z","level":"info","message":"VS Code extension activated","service":"yaraast","component":"vscode-yaraast","event_name":"extension.activated","operation":"extension.activate"}
```

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

Run focused Python logging tests with
`pytest --no-cov tests/test_logging_config.py tests/test_lsp_server_more.py tests/test_cli_lsp_command.py`;
the global coverage threshold applies to the full suite, so run `pytest` afterwards. The repository's
other Python quality gates are `ruff check .`, `mypy .`, `black --check .`, and `bandit -r yaraast`.
Run extension tests and checks from `vscode-yaraast` with `npm test`, `npm run lint`, `npm audit`,
and `npx vsce package --out /tmp/yaraast.vsix` followed by
`python3 scripts/verify_vsix.py /tmp/yaraast.vsix`.

## Final audit

| Dimension | Initial | Final | Evidence |
| --- | ---: | ---: | --- |
| Architecture and decoupling | 2 | 10 | Stdlib boundary leaves host logging untouched; VS Code helper accepts its output channel as a destination. |
| Functional coverage | 3 | 10 | CLI, named LSP feature/fallback paths, extension lifecycle, command failures, and runtime status are instrumented. |
| Event quality | 2 | 10 | Events include stable operation names, outcomes, durations where useful, and safe error types and frames. |
| Structure and consistency | 1 | 10 | Python and extension emit UTC JSON with normalized fields and allow-listed context. |
| Context and correlation | 1 | 10 | `ContextVar` covers threads/async tasks; pygls request IDs are reused; no IDs are fabricated. |
| Security and privacy | 3 | 10 | Redaction, control removal, size caps, payload filtering, generic UI errors, and trace-off default. |
| Performance and resilience | 6 | 10 | Bounded LSP metrics, low-volume events, destination-failure handling, and measured request overhead. |
| Configuration and portability | 3 | 10 | CLI environment/flags and stderr/JSON/text; extension uses native channels and trace setting. |
| Error handling | 2 | 10 | CLI/LSP/extension failures are visible at owning boundaries without logging exception messages. |
| Testing and verification | 2 | 10 | Python privacy/correlation/concurrency and extension lifecycle/redaction/concurrency tests pass. |
| **Mean** | **2.5** | **10.0** | Arithmetic mean across all ten applicable dimensions. |

The project has no database, outbound API client, authentication system, queue, scheduled worker, or
distributed service path, so those observability dimensions do not apply. Existing local LSP latency
summaries cover the metrics needed by this single-process application; no external metrics or tracing
backend is required for the current runtime model. The VS Code trace can contain source text only
after an explicit user opt-in; its default remains off. VS Code's output channel owns local display
and retention, while Python CLI events continue to use stderr.
