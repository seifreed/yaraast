# LSP Parity Report vs YARA-X

## Evidence Base

This report is grounded on:

- multi-dialect parity tests
- end-to-end LSP request tests
- runtime benchmarks
- current VS Code extension integration

Relevant suites:

- [tests/test_lsp_parity_multidialect_more.py](/Users/seifreed/tools/malware/yaraast/tests/test_lsp_parity_multidialect_more.py)
- [tests/test_lsp_parity_e2e.py](/Users/seifreed/tools/malware/yaraast/tests/test_lsp_parity_e2e.py)
- [scripts/benchmark_lsp_runtime.py](/Users/seifreed/tools/malware/yaraast/scripts/benchmark_lsp_runtime.py)
- [docs/benchmarks/lsp-runtime-latest.json](/Users/seifreed/tools/malware/yaraast/docs/benchmarks/lsp-runtime-latest.json)

## Equaled

- `hover`
- `definition`
- `references`
- `rename`
- `symbols`
- `documentLinks`
- `documentHighlight`
- `selectionRange`
- `semanticTokens/full`
- `semanticTokens/range`
- `textDocument/diagnostic`
- `workspaceFolders`
- `didChangeConfiguration`
- `didChangeWatchedFiles`

## Exceeded

- multi-dialect runtime support:
  - YARA
  - YARA-L
  - YARA-X
- structural authoring actions backed by:
  - optimizer
  - diff
  - round-trip serializer
  - AST tools
- runtime diagnostics and cache visibility in the extension
- persistent workspace index and cache-aware runtime status

## Still Partial

- compiler-backed diagnostics are stronger than before, but not every semantic fix comes from compiler-originated metadata
- some providers still retain fallback logic for local/no-runtime cases
- extension publication is technically ready, but marketplace assets and clean-install verification still need a final pass

## Recent parity gains

- structured quick fixes for:
  - missing imports
  - duplicate strings
  - unknown builtin functions
  - invalid arity with missing or extra arguments
- richer multi-dialect parity coverage for:
  - hover
  - definition
  - references
  - rename
  - symbols
  - document links
  - document highlight
  - selection range
  - semantic tokens by range

## Benchmarks

Current synthetic runtime benchmarks pass:

- single large document
- medium workspace
- large workspace

See:

- [scripts/benchmark_lsp_runtime.py](/Users/seifreed/tools/malware/yaraast/scripts/benchmark_lsp_runtime.py)

## Practical Conclusion

`yaraast` is no longer behind `yara-x` on core LSP protocol surface.

The remaining work is not basic parity. It is:

- hardening diagnostics further
- polishing residual fallback paths
- finishing product/publication quality
