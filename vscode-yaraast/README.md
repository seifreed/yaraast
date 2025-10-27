# YARAAST - YARA Language Support for VSCode

Powerful language support for YARA rules powered by the YARAAST AST parser.

## Features

### 🎯 Real-time Diagnostics
- **Syntax errors** highlighted as you type
- **Semantic validation** for undefined variables, missing imports
- **Best practices** warnings and suggestions

### ✨ Intelligent Autocomplete
- **Context-aware** completions
- **Module members** (pe.imphash, elf.type, etc.)
- **Built-in functions** (uint32, hash.md5, etc.)
- **String modifiers** (nocase, wide, xor, etc.)
- **Keywords** and **meta fields**

### 📖 Hover Information
- **Documentation** for keywords and functions
- **String definitions** with values and modifiers
- **Module information** with descriptions
- **Rule metadata** display

### 🔍 Code Navigation
- **Go to Definition** (F12) - Jump to string/rule definitions
- **Find All References** (Shift+F12) - Find all usages
- **Document Symbols** (Ctrl+Shift+O) - Outline view
- **Peek Definition** (Alt+F12)

### 🎨 Code Formatting
- **Format Document** (Shift+Alt+F)
- **Format Selection**
- Multiple formatting styles (default, compact, readable, verbose)

### 💡 Quick Fixes & Code Actions
- **Auto-import** missing modules
- **Add missing** string definitions
- **Rename** duplicate identifiers
- **Extract** to rule (refactoring)

### 🔄 Rename Symbol
- **Rename** string identifiers (F2)
- **Rename** rule names
- Updates all references automatically

### 🌈 Semantic Highlighting
- Advanced syntax highlighting based on AST analysis
- Distinguishes between different token types
- Better visual code understanding

### 🔤 Signature Help
- **Parameter hints** for functions (Ctrl+Shift+Space)
- See function signatures while typing
- Works with YARA modules (pe, hash, math, etc.)

### 🎯 Document Highlight
- **Auto-highlight** all occurrences of symbol under cursor
- Works with string identifiers ($str, #str, @str, !str)
- Visual feedback for symbol usage

### 📁 Folding Ranges
- **Collapse/expand** code sections
- Fold entire rules or individual sections (meta, strings, condition)
- Navigate large YARA files efficiently

### 🔗 Document Links
- **Clickable imports** with Ctrl+Click
- Opens documentation for YARA modules (pe, elf, hash, etc.)
- Navigate to included files

### 🔍 Workspace Symbols
- **Global search** across all YARA files (Ctrl+T)
- Find rules and strings in entire project
- Fast navigation in large codebases

## Installation

### Prerequisites

1. **Install yaraast with LSP support:**
   ```bash
   pip install 'yaraast[lsp]'
   ```

   Or from source:
   ```bash
   git clone https://github.com/seifreed/yaraast
   cd yaraast
   pip install -e '.[lsp]'
   ```

2. **Verify installation:**
   ```bash
   yaraast --version
   yaraast lsp --help
   ```

### Install Extension

#### From VSIX (Recommended)
1. Download the latest `.vsix` file from [releases](https://github.com/seifreed/yaraast/releases)
2. Open VSCode
3. Go to Extensions (Ctrl+Shift+X)
4. Click `...` menu → `Install from VSIX...`
5. Select the downloaded file

#### From Marketplace (Coming Soon)
Search for "YARAAST" in the VSCode Extensions marketplace

#### From Source
```bash
cd vscode-yaraast
npm install
npm run compile
# Then press F5 in VSCode to launch Extension Development Host
```

## Configuration

Open VSCode settings (`Ctrl+,`) and search for "yaraast":

### Language Server Settings

```json
{
  // Enable/disable the language server
  "yaraast.lsp.enabled": true,

  // Path to Python interpreter (must have yaraast[lsp] installed)
  "yaraast.lsp.pythonPath": "python",

  // Trace server communication (for debugging)
  "yaraast.lsp.trace.server": "off", // "off" | "messages" | "verbose"
}
```

### Formatting Settings

```json
{
  // Code formatting style
  "yaraast.formatting.style": "default", // "default" | "compact" | "readable" | "verbose"
}
```

### Diagnostics Settings

```json
{
  // Enable/disable diagnostics
  "yaraast.diagnostics.enabled": true
}
```

## Usage

### Quick Start

1. **Open a YARA file** (`.yar` or `.yara`)
2. **Start typing** - autocomplete and diagnostics work automatically
3. **Hover** over keywords for documentation
4. **Use F12** to jump to definitions
5. **Press Shift+Alt+F** to format

### Commands

Access via Command Palette (`Ctrl+Shift+P`):

- `YARAAST: Restart Language Server` - Restart the LSP server
- `YARAAST: Show Output Channel` - View server logs

### Keyboard Shortcuts

- **F12** - Go to Definition
- **Shift+F12** - Find All References
- **Alt+F12** - Peek Definition
- **F2** - Rename Symbol
- **Shift+Alt+F** - Format Document
- **Ctrl+Shift+O** - Go to Symbol (Outline)
- **Ctrl+Shift+Space** - Signature Help (Parameter Hints)
- **Ctrl+T** - Workspace Symbols (Global Search)
- **Ctrl+Click** - Follow Document Links (imports/includes)

## Supported YARA Dialects

- ✅ **Standard YARA** - Full support
- ✅ **YARA-X** - VirusTotal's next-gen YARA
- ✅ **YARA-L** - Google Chronicle detection rules

## Troubleshooting

### Language Server Not Starting

1. **Check Python installation:**
   ```bash
   python --version
   which python
   ```

2. **Verify yaraast is installed:**
   ```bash
   python -m yaraast --version
   ```

3. **Check LSP dependencies:**
   ```bash
   pip list | grep -E "pygls|lsprotocol"
   ```

4. **View server logs:**
   - Open Command Palette (`Ctrl+Shift+P`)
   - Run `YARAAST: Show Output Channel`

### Python Path Issues

If using a virtual environment or custom Python installation:

1. Open VSCode settings
2. Set `yaraast.lsp.pythonPath` to your Python path:
   ```json
   {
     "yaraast.lsp.pythonPath": "/path/to/your/python"
   }
   ```

### Performance Issues

For large YARA files:

1. Disable diagnostics temporarily:
   ```json
   {
     "yaraast.diagnostics.enabled": false
   }
   ```

2. Increase timeout in settings (if available)

## Examples

### Autocomplete in Action

```yara
rule example {
    meta:
        author = "analyst"  // ← autocomplete suggests common meta fields
    strings:
        $hex = { 4D 5A }
        $text = "malware" nocase wide  // ← autocomplete for modifiers
    condition:
        pe.     // ← autocomplete shows: imphash(), number_of_sections, etc.
        ^^^
}
```

### Quick Fix Example

```yara
rule test {
    condition:
        pe.imphash() == "abc123"  // ❌ Module 'pe' not imported
                                  // 💡 Quick fix: "Add import \"pe\""
}
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md)

## License

MIT License - see [LICENSE](../LICENSE)

## Author

**Marc Rivero** (@seifreed)
- Email: mriverolopez@gmail.com
- GitHub: [https://github.com/seifreed/yaraast](https://github.com/seifreed/yaraast)

## Related Projects

- **YARAAST CLI** - [https://github.com/seifreed/yaraast](https://github.com/seifreed/yaraast)
- **YARA** - [https://github.com/VirusTotal/yara](https://github.com/VirusTotal/yara)
- **YARA-X** - [https://github.com/VirusTotal/yara-x](https://github.com/VirusTotal/yara-x)
