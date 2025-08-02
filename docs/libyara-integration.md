# LibYARA Integration

YaraAST provides optional integration with libyara (the official YARA library) for cross-validation and equivalence testing. This allows you to:

- Compile AST to libyara rules
- Scan data using the official YARA engine
- Cross-validate between yaraast evaluation and libyara
- Test AST round-trip equivalence

## Installation

The libyara integration requires the `yara-python` package:

```bash
# Install with libyara support
pip install yaraast[libyara]

# Or install separately
pip install yara-python
```

## Features

### 1. AST to LibYARA Compilation

Convert yaraast AST to compiled libyara rules:

```python
from yaraast.parser import Parser
from yaraast.libyara import LibyaraCompiler

# Parse rules
parser = Parser()
ast = parser.parse(rule_text)

# Compile with libyara
compiler = LibyaraCompiler()
result = compiler.compile_ast(ast)

if result.success:
    # Use compiled rules for scanning
    rules = result.compiled_rules
else:
    print("Compilation errors:", result.errors)
```

### 2. Scanning with LibYARA

Scan files or data using compiled rules:

```python
from yaraast.libyara import LibyaraScanner

scanner = LibyaraScanner(timeout=60)

# Scan data
result = scanner.scan_data(rules, data)
if result.matched:
    for match in result.matches:
        print(f"Matched: {match.rule}")
        for string in match.strings:
            print(f"  {string['identifier']} at {string['offset']}")

# Scan file
result = scanner.scan_file(rules, "malware.exe")
```

### 3. Cross-Validation

Validate that yaraast evaluation produces the same results as libyara:

```python
from yaraast.libyara.cross_validator import CrossValidator

validator = CrossValidator()
result = validator.validate(ast, test_data)

if result.valid:
    print("✓ Validation passed!")
else:
    print("✗ Differences found:")
    for diff in result.rules_differ:
        print(f"  - {diff}")
```

### 4. Round-Trip Equivalence Testing

Test that AST → code → libyara → re-parse produces equivalent results:

```python
from yaraast.libyara import EquivalenceTester

tester = EquivalenceTester()
result = tester.test_round_trip(ast, test_data)

if result.equivalent:
    print("✓ Round-trip successful!")
else:
    if result.ast_differences:
        print("AST differences:", result.ast_differences)
    if result.compilation_errors:
        print("Compilation errors:", result.compilation_errors)
```

## CLI Commands

### Cross-Validation

Compare yaraast evaluation with libyara scanning:

```bash
# Basic validation
yaraast validate cross rules.yar sample.exe

# With external variables
yaraast validate cross rules.yar data.bin -e filename=data.bin -e filetype=PE

# Verbose output
yaraast validate cross rules.yar malware.bin -v
```

### Round-Trip Testing

Test AST transformation equivalence:

```bash
# Test round-trip without scanning
yaraast validate roundtrip rules.yar

# Test with scanning comparison
yaraast validate roundtrip rules.yar -d test.bin

# Verbose mode shows code comparison
yaraast validate roundtrip rules.yar -v
```

## API Reference

### LibyaraCompiler

Compiles AST or source code to libyara rules.

```python
class LibyaraCompiler:
    def __init__(self, externals: Optional[Dict[str, Any]] = None)
    
    def compile_ast(self, ast: YaraFile, 
                   includes: Optional[Dict[str, str]] = None,
                   error_on_warning: bool = False) -> CompilationResult
    
    def compile_source(self, source: str,
                      includes: Optional[Dict[str, str]] = None,
                      error_on_warning: bool = False) -> CompilationResult
    
    def compile_file(self, filepath: Union[str, Path],
                    error_on_warning: bool = False) -> CompilationResult
    
    def save_compiled_rules(self, rules: Any, filepath: Union[str, Path]) -> bool
```

### LibyaraScanner

Scans data/files using compiled rules.

```python
class LibyaraScanner:
    def __init__(self, timeout: Optional[int] = None)
    
    def scan_data(self, rules: Any, data: bytes,
                  fast_mode: bool = False) -> ScanResult
    
    def scan_file(self, rules: Any, filepath: Union[str, Path],
                  fast_mode: bool = False) -> ScanResult
    
    def scan_process(self, rules: Any, pid: int) -> ScanResult
```

### CrossValidator

Validates consistency between yaraast and libyara.

```python
class CrossValidator:
    def validate(self, ast: YaraFile, test_data: bytes,
                externals: Optional[Dict[str, Any]] = None) -> ValidationResult
    
    def validate_batch(self, ast: YaraFile, 
                      test_data_list: List[bytes],
                      externals: Optional[Dict[str, Any]] = None) -> List[ValidationResult]
```

### EquivalenceTester

Tests AST round-trip equivalence.

```python
class EquivalenceTester:
    def test_round_trip(self, original_ast: YaraFile,
                       test_data: Optional[bytes] = None) -> EquivalenceResult
    
    def test_file_round_trip(self, filepath: str,
                           test_data: Optional[bytes] = None) -> EquivalenceResult
```

## Use Cases

### 1. Testing YARA Rule Changes

Ensure rule modifications don't change detection behavior:

```python
# Original rules
original = parser.parse_file("rules_v1.yar")
modified = parser.parse_file("rules_v2.yar") 

# Test on malware samples
for sample in malware_samples:
    orig_result = validator.validate(original, sample)
    mod_result = validator.validate(modified, sample)
    
    if orig_result.yaraast_results != mod_result.yaraast_results:
        print(f"Detection changed for {sample}")
```

### 2. Performance Comparison

Compare yaraast evaluation with libyara performance:

```python
result = validator.validate(ast, large_file)

print(f"YaraAST time: {result.yaraast_time:.3f}s")
print(f"LibYARA time: {result.libyara_scan_time:.3f}s")
print(f"Speedup: {result.yaraast_time / result.libyara_scan_time:.1f}x")
```

### 3. CI/CD Integration

Validate rules in continuous integration:

```yaml
# .github/workflows/validate.yml
- name: Validate YARA rules
  run: |
    yaraast validate roundtrip rules/*.yar
    yaraast validate cross rules/*.yar tests/samples/* -v
```

### 4. Rule Development

Test rules during development without full YARA installation:

```python
# Use yaraast for quick iteration
evaluator = YaraEvaluator(test_data)
result = evaluator.evaluate_file(ast)

# Validate with libyara before deployment
if YARA_AVAILABLE:
    validation = validator.validate(ast, test_data)
    assert validation.valid
```

## Limitations

1. **Module Support**: Not all YARA modules may be fully supported in mock implementations
2. **Performance**: The yaraast evaluator is designed for correctness, not performance
3. **Feature Parity**: Some advanced YARA features may not be implemented in the evaluator

## Troubleshooting

### yara-python Installation Issues

On some systems, installing yara-python requires the YARA library:

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev libjansson-dev
pip install yara-python

# macOS
brew install yara
pip install yara-python

# Windows
# Download pre-built wheels from:
# https://github.com/VirusTotal/yara-python/releases
```

### Import Errors

If you get import errors, ensure yara-python is installed:

```python
try:
    from yaraast.libyara import LibyaraCompiler
    print("LibYARA integration available")
except ImportError:
    print("Install with: pip install yaraast[libyara]")
```
