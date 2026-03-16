# Release Checklist

This checklist keeps VSIX publication reproducible.

## Local package validation

1. Install extension dependencies:
   ```bash
   npm install
   ```
2. Compile the extension:
   ```bash
   npm run compile
   ```
3. Package the extension:
   ```bash
   npm run package
   ```
4. Verify the packaged VSIX contents:
   ```bash
   npm run verify:vsix
   ```

## Manual install validation

Run these steps in a clean VS Code profile when the `code` CLI is available.
If it is not on `PATH`, use the app-bundled binary:

```bash
"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
```

Verification evidence for the current package lives in [INSTALL-VERIFICATION.md](./INSTALL-VERIFICATION.md).

1. Install the generated VSIX:
   ```bash
   code --install-extension yaraast-0.1.0.vsix --force
   ```
2. Open a `.yar` or `.yara` file.
3. Confirm:
   - syntax highlighting is active
   - the language server starts
   - `YARAAST: Show Server Status` works
   - `YARAAST: Preview Refactors` returns actions on a rule
   - formatting and hover work

## Marketplace assets

Before publishing, confirm:

- `README.md` reflects current commands/settings
- `CHANGELOG.md` includes the release
- icon files are present
- screenshots or animated captures are ready for the marketplace listing
