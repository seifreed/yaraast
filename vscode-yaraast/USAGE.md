# YARAAST Extension Usage

## Install

1. Install the Python package with LSP support:
   ```bash
   pip install 'yaraast[lsp]'
   ```
2. Install the VSIX:
   ```bash
   code --install-extension yaraast-0.1.0.vsix
   ```

## First Run

1. Open a `.yar` or `.yara` file.
2. Run `YARAAST: Show Server Status`.
3. If the server does not start, run `YARAAST: Diagnose Server Environment`.

## Useful Commands

- `YARAAST: Show Server Status`
- `YARAAST: Show Runtime Metrics`
- `YARAAST: Copy Server Status`
- `YARAAST: Preview Refactors`
- `YARAAST: Select Dialect Mode`
- `YARAAST: Restart Language Server`

## Recommended Workflow

1. Keep `yaraast.lsp.cacheWorkspace` enabled for cross-file navigation.
2. Use `YARAAST: Preview Refactors` before applying structural edits.
3. Use `YARAAST: Show Runtime Metrics` when validating large workspaces.
