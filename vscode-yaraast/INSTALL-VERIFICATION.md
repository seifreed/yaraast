# VSIX Install Verification

## Command

```bash
"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" \
  --user-data-dir "<tmp-user-data>" \
  --extensions-dir "<tmp-extensions>" \
  --install-extension "$(pwd)/vscode-yaraast/yaraast-0.1.0.vsix" \
  --force
```

## Result

- extension installed successfully
- extension listed successfully:

```text
seifreed.yaraast@0.1.0
```

## Notes

- this verification used isolated temporary directories for:
  - user data
  - extensions
- it does not rely on an existing VS Code profile
