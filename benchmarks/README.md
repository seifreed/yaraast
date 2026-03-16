# YARA AST Parser Benchmarking Suite

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.

This benchmarking suite provides comprehensive performance testing and profiling tools for the YARA AST Parser project.

## Overview

The benchmarking suite enables you to:

- **Generate realistic test files** of varying sizes (5MB - 50MB)
- **Benchmark parser performance** comparing standard Parser vs StreamingParser
- **Profile memory usage** with detailed snapshots and statistics
- **Profile CPU usage** with cProfile for bottleneck identification
- **Track performance regressions** using pytest-benchmark integration

## Directory Structure

```
benchmarks/
├── __init__.py                  # Package initialization
├── README.md                    # This file
├── conftest.py                  # Pytest configuration
├── test_file_generator.py       # YARA test file generator
├── benchmark_large_files.py     # Main benchmarking script
├── memory_profiler.py           # Memory profiling utilities
├── profiler.py                  # cProfile integration
├── test_benchmarks.py           # Pytest-benchmark tests
├── test_data/                   # Generated test files (gitignored)
│   ├── test_rules_5mb.yar
│   ├── test_rules_10mb.yar
│   ├── test_rules_18mb.yar
│   ├── test_rules_20mb.yar
│   └── test_rules_50mb.yar
└── results/                     # Benchmark results (gitignored)
    ├── benchmark_results.json
    ├── benchmark_report.txt
    ├── profile_*.prof
    ├── profile_*.txt
    └── memory_profile_*.txt
```

## Prerequisites

Install the required dependencies:

```bash
# Install benchmarking dependencies
pip install psutil pytest-benchmark

# Optional: Install visualization tools
pip install snakeviz gprof2dot
```

Or install from the project's optional dependencies:

```bash
pip install -e ".[performance]"
```

## Quick Start

### 1. Generate Test Files

First, generate realistic YARA test files:

```bash
cd benchmarks
python test_file_generator.py
```

This creates test files in `benchmarks/test_data/`:
- `test_rules_5mb.yar` - Small file for quick tests
- `test_rules_10mb.yar` - Medium file for scaling tests
- `test_rules_18mb.yar` - Large file for stress testing
- `test_rules_20mb.yar` - Extra large file
- `test_rules_50mb.yar` - Maximum stress test

**Expected output:**
```
YARA Test File Generator
==================================================

Generating 5MB test file...
Generated 100 rules (1.02 MB)
Generated 200 rules (2.05 MB)
...
Created: benchmarks/test_data/test_rules_5mb.yar
  Rules: 450
  Actual size: 5.02 MB
```

### 2. Run Basic Benchmarks

Execute the main benchmarking suite:

```bash
python benchmark_large_files.py
```

**Expected output:**
```
YARA AST Parser Benchmarking Suite
============================================================

============================================================
Comparing parsers on: test_rules_5mb.yar
File size: 5.02 MB
============================================================

Benchmarking standard Parser on test_rules_5mb.yar...
  Performing warmup run...
  Success! Parsed 450 rules in 0.234s
  Throughput: 1923.08 rules/s, 21.45 MB/s
  Memory: 15.32 MB

Benchmarking StreamingParser on test_rules_5mb.yar...
  Performing warmup run...
  Success! Parsed 450 rules in 0.267s
  Throughput: 1685.39 rules/s, 18.80 MB/s
  Memory: 12.45 MB

  Comparison:
  Metric                         Standard        Streaming       Difference
  ---------------------------------------------------------------------------
  Parse Time (s)                 0.234           0.267           +14.1%
  Peak Memory (MB)               15.32           12.45           -18.7%
  Throughput (rules/s)           1923.08         1685.39         -12.4%
```

### 3. Run Memory Profiling

Profile memory usage with detailed snapshots:

```bash
python memory_profiler.py
```

**Expected output:**
```
YARA AST Parser Memory Profiler
============================================================

============================================================
Memory profiling: test_rules_5mb.yar
File size: 5.02 MB
============================================================

Profiling Standard Parser...
  Parse Time: 0.234 seconds
  Peak RSS: 15.32 MB
  Average RSS: 12.78 MB
  Memory Growth: 14.56 MB
  Snapshots: 5

Profiling StreamingParser...
  Parse Time: 0.267 seconds
  Peak RSS: 12.45 MB
  Average RSS: 10.23 MB
  Memory Growth: 11.89 MB
  Snapshots: 8

  Memory Comparison:
  Metric                         Standard        Streaming       Difference
  ---------------------------------------------------------------------------
  Peak RSS (MB)                  15.32           12.45           -18.7%
  Average RSS (MB)               12.78           10.23           -20.0%
  Memory Growth (MB)             14.56           11.89           -18.3%
```

### 4. Run CPU Profiling

Generate detailed cProfile reports:

```bash
python profiler.py
```

This generates:
- `.prof` files for interactive analysis
- `.txt` files with human-readable reports
- Comparison reports between parsers

**Expected files:**
```
results/
├── profile_standard_test_rules_5mb.prof
├── profile_standard_test_rules_5mb.txt
├── profile_streaming_test_rules_5mb.prof
├── profile_streaming_test_rules_5mb.txt
└── profile_comparison_test_rules_5mb.txt
```

### 5. Run Pytest Benchmarks

Execute automated regression tests:

```bash
# Run all benchmarks
pytest test_benchmarks.py -v --benchmark-only

# Run with detailed statistics
pytest test_benchmarks.py -v --benchmark-only --benchmark-verbose

# Save baseline for future comparisons
pytest test_benchmarks.py --benchmark-only --benchmark-save=baseline

# Compare against baseline
pytest test_benchmarks.py --benchmark-only --benchmark-compare=baseline

# Skip slow tests
pytest test_benchmarks.py -v --benchmark-only -m "not slow"
```

**Expected output:**
```
======================== test session starts =========================
test_benchmarks.py::TestParserBenchmarks::test_benchmark_small_file_parsing PASSED
test_benchmarks.py::TestParserBenchmarks::test_benchmark_medium_file_parsing PASSED
test_benchmarks.py::TestStreamingParserBenchmarks::test_benchmark_streaming_small_file PASSED

---------------------------- benchmark: 3 tests ----------------------------
Name (time in ms)                                    Min      Max     Mean
----------------------------------------------------------------------------
test_benchmark_small_file_parsing                 230.45  245.67  234.12
test_benchmark_medium_file_parsing                456.78  489.23  467.34
test_benchmark_streaming_small_file               262.34  278.90  267.45
----------------------------------------------------------------------------
```

## Detailed Usage

### Test File Generator

Generate custom test files:

```python
from pathlib import Path
from test_file_generator import YaraTestFileGenerator

generator = YaraTestFileGenerator(seed=42)

# Generate a 100MB file with custom complexity mix
stats = generator.generate_file(
    target_size_mb=100,
    output_path=Path("custom_test.yar"),
    complexity_mix={
        "simple": 0.1,    # 10% simple rules
        "medium": 0.6,    # 60% medium rules
        "complex": 0.3,   # 30% complex rules
    }
)

print(f"Generated {stats['rule_count']} rules")
```

### Benchmark Programmatically

Use the benchmarking API:

```python
from pathlib import Path
from benchmark_large_files import ParserBenchmark

benchmark = ParserBenchmark(results_dir=Path("results"))

# Benchmark a specific file
test_file = Path("test_data/test_rules_5mb.yar")
results = benchmark.benchmark_comparison(test_file, warmup=True)

# Save results
benchmark.save_results("my_benchmark.json")
benchmark.generate_report("my_report.txt")
```

### Memory Profiling API

Profile memory usage programmatically:

```python
from pathlib import Path
from memory_profiler import MemoryProfiler

profiler = MemoryProfiler(sampling_interval=0.1)

# Profile both parsers
results = profiler.compare_parsers(
    Path("test_data/test_rules_10mb.yar"),
    detailed=True
)

# Save profiles
for parser_type, profile in results.items():
    profiler.save_profile(
        profile,
        Path(f"memory_{parser_type}.txt")
    )
```

### CPU Profiling API

Profile CPU usage programmatically:

```python
from pathlib import Path
from profiler import ParserProfiler

profiler = ParserProfiler(results_dir=Path("results"))

# Profile both parsers
results = profiler.compare_parsers(
    Path("test_data/test_rules_10mb.yar")
)

# Stats objects available for analysis
standard_stats = results["standard"]
streaming_stats = results["streaming"]
```

## Understanding Results

### Benchmark Metrics

**Parse Time**: Total time to parse the file
- Lower is better
- Should scale linearly with file size
- Watch for exponential growth (algorithmic issues)

**Peak Memory**: Maximum memory used during parsing
- Lower is better for StreamingParser
- Standard parser loads entire file
- StreamingParser should show constant memory usage

**Throughput**: Rules parsed per second
- Higher is better
- Should remain consistent across file sizes
- Variance indicates scaling issues

**MB/s**: File size processed per second
- Complements rules/s metric
- Accounts for rule complexity
- Useful for I/O-bound analysis

### Profile Analysis

#### Reading cProfile Reports

The `.txt` reports are sorted by:

1. **Cumulative Time**: Time spent in function and all callees
   - Identifies high-level bottlenecks
   - Look for unexpected expensive operations

2. **Total Time**: Time spent in function itself
   - Identifies computational hotspots
   - Pure function execution time

3. **Callers**: Who called the function
   - Traces execution paths
   - Identifies call patterns

#### Memory Profile Reports

**Snapshots** show memory at key points:
- Before parsing
- After reading file
- After creating parser
- After parsing
- After cleanup

**Key Metrics**:
- **Memory Growth**: Delta from start to end
- **Peak RSS**: Maximum resident memory
- **Average RSS**: Mean memory during parsing

## Interpreting Results

### Good Performance Indicators

- Linear scaling with file size
- Consistent throughput across runs
- StreamingParser uses less memory than standard
- No memory leaks (cleanup reduces memory)
- cProfile shows expected hotspots (lexer, parser core)

### Warning Signs

- Quadratic or exponential time growth
- Memory usage proportional to file size for streaming
- Throughput degradation on larger files
- Unexpected functions in cProfile top 10
- Memory not released after cleanup

## Continuous Performance Testing

### Establishing Baselines

```bash
# Create baseline with current code
pytest test_benchmarks.py --benchmark-only --benchmark-save=v0.6.0

# After changes, compare
pytest test_benchmarks.py --benchmark-only --benchmark-compare=v0.6.0
```

### CI/CD Integration

Add to your CI pipeline:

```yaml
- name: Run performance benchmarks
  run: |
    pip install pytest-benchmark psutil
    cd benchmarks
    python test_file_generator.py
    pytest test_benchmarks.py --benchmark-only --benchmark-json=../results.json
```

### Regression Detection

Set up automated alerts:

```bash
# Fail if performance regresses > 10%
pytest test_benchmarks.py --benchmark-only \
  --benchmark-compare=baseline \
  --benchmark-compare-fail=mean:10%
```

## Visualization

### Visualize cProfile Results

```bash
# Interactive HTML visualization
pip install snakeviz
snakeviz results/profile_standard_test_rules_5mb.prof

# Generate call graph
pip install gprof2dot
gprof2dot -f pstats results/profile_standard_test_rules_5mb.prof \
  | dot -Tpng -o callgraph.png
```

### Custom Visualization

```python
import json
import matplotlib.pyplot as plt

# Load benchmark results
with open("results/benchmark_results.json") as f:
    data = json.load(f)

# Plot throughput comparison
# ... (custom visualization code)
```

## Best Practices

1. **Always run warmup iterations** to eliminate cold start effects
2. **Close other applications** during benchmarking for consistency
3. **Run multiple iterations** to account for variance
4. **Compare same file sizes** when evaluating optimizations
5. **Check for memory leaks** by examining cleanup snapshots
6. **Profile before optimizing** to identify real bottlenecks
7. **Establish baselines** before making changes
8. **Track metrics over time** to catch regressions early

## Troubleshooting

### No test files found

```bash
cd benchmarks
python test_file_generator.py
```

### pytest-benchmark not installed

```bash
pip install pytest-benchmark
```

### Memory profiling errors

Ensure psutil is installed:
```bash
pip install psutil
```

### Large files cause OOM

Reduce test file sizes or use StreamingParser exclusively:
```python
# In test_file_generator.py, modify sizes_mb
sizes_mb = [1, 2, 5, 10]  # Smaller files
```

## Advanced Topics

### Custom Benchmark Scenarios

Create custom benchmark scenarios by modifying test file generation:

```python
# Generate files with specific characteristics
generator = YaraTestFileGenerator()

# High string count per rule
rule = generator.generate_rule(complexity="complex")

# Specific string types
hex_string = generator.generate_hex_string()
regex_string = generator.generate_regex_string()
```

### Micro-benchmarks

Create focused benchmarks for specific operations:

```python
@pytest.mark.benchmark
def test_hex_string_parsing(benchmark):
    """Benchmark hex string parsing specifically."""

    hex_rule = '''
    rule test {
        strings:
            $hex = { 4D 5A ?? ?? [0-10] 50 45 00 00 }
        condition:
            $hex at 0
    }
    '''

    def parse_hex():
        parser = Parser(hex_rule)
        return parser.parse()

    result = benchmark(parse_hex)
    assert len(result.rules) == 1
```

### Memory Leak Detection

Use memory profiling to detect leaks:

```python
from memory_profiler import MemoryProfiler

profiler = MemoryProfiler()

# Parse multiple times
for i in range(100):
    profile = profiler.profile_standard_parser(test_file)

    if i > 0 and profile.memory_growth_mb > previous.memory_growth_mb:
        print(f"Warning: Memory growth increasing at iteration {i}")

    previous = profile
```

## Contributing

When contributing performance improvements:

1. Run baseline benchmarks before changes
2. Make your optimization
3. Run benchmarks again
4. Compare results
5. Include benchmark data in PR
6. Verify no regressions in other metrics

## License

All benchmark code is licensed under GPLv3. See the LICENSE file in the project root for details.

## Support

For issues or questions about benchmarking:

- Open an issue on GitHub
- Include benchmark results and environment details
- Provide reproducible test cases

## References

- pytest-benchmark: https://pytest-benchmark.readthedocs.io/
- cProfile: https://docs.python.org/3/library/profile.html
- psutil: https://psutil.readthedocs.io/
- YARA documentation: https://yara.readthedocs.io/
