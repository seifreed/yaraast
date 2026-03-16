# LSP Runtime Architecture

## Overview

`yaraast.lsp.runtime` is the shared execution core for the language server.

The design goal is simple:

- one structural model for a document
- one runtime for workspace state
- minimal provider-specific parsing

Providers such as `hover`, `definition`, `references`, `rename`, `symbols` and `document_links`
should consume `DocumentContext` and `LspRuntime`, not rebuild local state ad hoc.

## DocumentContext

`DocumentContext` represents one document revision.

It owns:

- source text
- parsed AST
- detected/forced dialect
- indexed symbols
- per-revision structural caches

### Main responsibilities

- parse source through `UnifiedParser`
- expose indexed `SymbolRecord` objects
- resolve symbols by position
- expose structural helpers for:
  - rules
  - strings
  - meta
  - sections
  - imports
  - includes
  - module members

### Cache model

Per-document caches are keyed by `revision_key()`, which combines:

- document version
- SHA1 of source text

When the document changes, `update(...)` clears:

- AST
- parse errors
- line cache
- symbol indexes
- structural analysis cache

This keeps correctness simple and avoids stale cross-provider state.

Common indexed helpers exposed by `DocumentContext` include:

- `resolve_symbol(...)`
- `find_symbol_record(...)`
- `get_rule_info(...)`
- `get_rule_meta_items(...)`
- `get_rule_string_identifiers(...)`
- `get_rule_sections(...)`
- `get_string_definition_info(...)`
- `get_module_info(...)`
- `get_module_member_info(...)`
- `get_include_info(...)`
- `get_include_target_uri(...)`
- `get_local_rule_link_records()`

Providers should prefer these helpers over local parsing, line scans, or ad hoc regexes.

## LspRuntime

`LspRuntime` is the workspace coordinator.

It owns:

- open documents
- persisted workspace index
- workspace folders
- latency metrics
- debounce state
- cross-file navigation caches

### Main responsibilities

- open/update/save/close documents
- keep a persistent workspace index
- answer workspace symbol queries
- answer cross-file rule definition/reference queries
- expose runtime status and latency metrics

## Cache and invalidation

There are two layers:

### 1. Per-document caches

Inside `DocumentContext`:

- AST
- symbol indexes
- `resolve_symbol(...)`
- structural helpers such as `get_rule_info(...)`
- local rule link records
- module/include lookup helpers

These are invalidated when the document revision changes.

### 2. Workspace-level caches

Inside `LspRuntime`:

- workspace symbol query cache
- cross-file rule definition cache
- cross-file rule references cache
- per-document rule link cache
- cross-file rule reference record cache

These are invalidated through `_bump_workspace_generation()`.

Anything that changes effective workspace structure should bump the generation, including:

- watched file changes
- syncing dirty documents into the index
- cross-file updates affecting rules/symbols

## Workspace index

The workspace index is persisted under:

- `.yaraast/lsp-workspace-index.json`

It stores serialized `SymbolRecord` values and supports:

- fast reload of known workspace symbols
- lower startup cost
- cross-file symbol lookup without reparsing every file on each request

Queries merge:

- persisted records from disk
- live overlays for open or dirty documents

This keeps `workspaceSymbols` and cross-file navigation correct even before a dirty buffer is flushed.

## Performance hooks

The runtime currently exposes:

- debounce decisions
- latency metrics per operation
- cache counts in `get_status()`

This is the base for:

- runtime diagnostics in the extension
- workspace-scale benchmarks
- regression tracking for hot LSP paths

## Benchmarks

Synthetic runtime benchmarks live in:

- [scripts/benchmark_lsp_runtime.py](/Users/seifreed/tools/malware/yaraast/scripts/benchmark_lsp_runtime.py)

Current scenarios:

- single large document
- medium workspace
- large workspace

The benchmark reports:

- operation latency
- cache stats
- threshold failures

Use it when changing:

- cache keys
- invalidation logic
- workspace indexing
- cross-file navigation paths

Latest generated benchmark artifact:

- [docs/benchmarks/lsp-runtime-latest.json](/Users/seifreed/tools/malware/yaraast/docs/benchmarks/lsp-runtime-latest.json)

Regenerate it with:

```bash
venv/bin/python scripts/benchmark_lsp_runtime.py docs/benchmarks/lsp-runtime-latest.json
```
