# Final LSP Status

## Igualado

- `hover`
- `completion`
- `definition`
- `references`
- `rename`
- `document symbols`
- `workspace symbols`
- `selection range`
- `semantic tokens` full/range
- `document diagnostics`
- `document highlight`
- `document links`
- `formatting`
- `didChangeConfiguration`
- `didChangeWatchedFiles`
- `workspaceFolders`

## Superado

- refactors estructurales propios de `yaraast`
- tooling de authoring integrado con:
  - optimizer
  - diff estructural
  - round-trip seguro
  - AST formatter
- runtime dashboard y métricas expuestas al editor
- soporte multi-dialecto base en el mismo runtime:
  - YARA
  - YARA-L
  - YARA-X

## Pendiente

- más casos `compiler-backed` en `diagnostics.py`
- más quick fixes puramente estructurados en `code_actions.py`
- pulido fino residual en:
  - `hover.py`
  - `symbols.py`
  - `document_links.py`
- publicación final de la extensión con assets definitivos de marketplace

## Validación actual

- suite global:
  - `venv/bin/pytest -q -o addopts='' tests --ignore=tests/test_cli_comprehensive.py --cov=yaraast --cov-report=term-missing`
- resultado:
  - `2386 passed, 4 skipped`
  - `TOTAL 97.16%`

## Benchmarks

- latest:
  - [docs/benchmarks/lsp-runtime-latest.json](/Users/seifreed/tools/malware/yaraast/docs/benchmarks/lsp-runtime-latest.json)
  - [docs/benchmarks/lsp-runtime-latest.md](/Users/seifreed/tools/malware/yaraast/docs/benchmarks/lsp-runtime-latest.md)
- history:
  - `docs/benchmarks/history/`

## VSIX

- artefacto:
  - [yaraast-0.1.0.vsix](/Users/seifreed/tools/malware/yaraast/vscode-yaraast/yaraast-0.1.0.vsix)
- verificación de instalación limpia:
  - realizada con el binario interno de VS Code:
    - `/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code`
