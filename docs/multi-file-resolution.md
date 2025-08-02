# Multi-File Resolution

YaraAST supports comprehensive multi-file analysis with include resolution, dependency tracking, and workspace management.

## Features

### 1. Include Resolution
- **Path Searching**: Searches for includes in multiple directories
- **Caching**: Caches parsed files to improve performance
- **Cycle Detection**: Detects and reports circular includes
- **Checksum Validation**: Re-parses files when they change

### 2. Workspace Analysis
- **Directory Scanning**: Analyze entire directories of YARA files
- **Parallel Processing**: Analyze multiple files concurrently
- **Comprehensive Reports**: Get detailed analysis of all files

### 3. Dependency Graphs
- **Visual Representation**: Export dependency graphs in DOT format
- **Transitive Dependencies**: Track all dependencies recursively
- **Cycle Detection**: Find circular dependencies
- **Impact Analysis**: See which files depend on a given file

## Usage

### CLI Commands

#### Resolve Includes
```bash
# Resolve all includes for a single file
yaraast workspace resolve main.yar

# With additional search paths
yaraast workspace resolve main.yar -I /path/to/libs -I /path/to/common

# Show include tree
yaraast workspace resolve main.yar --show-tree
```

#### Analyze Workspace
```bash
# Analyze all YARA files in a directory
yaraast workspace analyze /path/to/rules

# With specific pattern and recursive search
yaraast workspace analyze /path/to/rules -p "*.yara" -r

# Generate JSON report
yaraast workspace analyze /path/to/rules -f json -o report.json

# Generate text report
yaraast workspace analyze /path/to/rules -f text -o report.txt
```

#### Generate Dependency Graph
```bash
# Generate DOT file for visualization
yaraast workspace graph /path/to/rules -o deps.dot

# Visualize with Graphviz
dot -Tpng deps.dot -o deps.png

# Generate JSON graph
yaraast workspace graph /path/to/rules -f json -o deps.json
```

### Python API

#### Include Resolution
```python
from yaraast.resolution import IncludeResolver

# Create resolver with search paths
resolver = IncludeResolver(search_paths=[
    "/usr/local/yara/includes",
    "/opt/yara/lib"
])

# Resolve a file and all its includes
resolved = resolver.resolve_file("main.yar")

# Access all rules (including from includes)
all_rules = resolved.get_all_rules()

# Get include tree
tree = resolver.get_include_tree("main.yar")
```

#### Workspace Analysis
```python
from yaraast.resolution import Workspace

# Create workspace
workspace = Workspace(root_path="/path/to/rules")

# Add files
workspace.add_file("rule1.yar")
workspace.add_directory("/path/to/more/rules", recursive=True)

# Analyze
report = workspace.analyze(parallel=True)

# Access results
print(f"Total rules: {report.total_rules}")
print(f"Total errors: {report.statistics['total_errors']}")

# Find specific rule
file_path, rule = workspace.find_rule("suspicious_behavior")

# Get dependencies
deps = workspace.get_file_dependencies("main.yar")
dependents = workspace.get_file_dependents("common.yar")
```

#### Dependency Graph
```python
from yaraast.resolution import DependencyGraph

graph = DependencyGraph()

# Add files to graph
graph.add_file(Path("file1.yar"), ast1)
graph.add_file(Path("file2.yar"), ast2)

# Check for cycles
cycles = graph.find_cycles()
if cycles:
    print(f"Found cycles: {cycles}")

# Get statistics
stats = graph.get_statistics()
print(f"Total nodes: {stats['total_nodes']}")
print(f"Dependency cycles: {stats['cycles']}")

# Export for visualization
dot_content = graph.export_dot()
```

## Environment Variables

### YARA_INCLUDE_PATH
Set additional search paths for include files:
```bash
export YARA_INCLUDE_PATH="/usr/local/yara/includes:/opt/yara/lib"
```

Multiple paths are separated by `:` on Unix or `;` on Windows.

## Example: Complete Workspace Analysis

```python
from yaraast.resolution import Workspace

# Setup workspace
ws = Workspace(
    root_path="/home/user/malware-rules",
    search_paths=["/usr/share/yara/includes"]
)

# Add all YARA files
ws.add_directory(".", pattern="*.yar", recursive=True)

# Analyze
report = ws.analyze(parallel=True)

# Print summary
print(f"Analyzed {report.files_analyzed} files")
print(f"Found {report.total_rules} rules")

# Check for issues
if report.global_errors:
    print("\nGlobal Issues:")
    for error in report.global_errors:
        print(f"  - {error}")

# Check individual files
for file_path, result in report.file_results.items():
    if result.errors or result.warnings:
        print(f"\n{file_path}:")
        for error in result.errors:
            print(f"  ERROR: {error}")
        for warning in result.warnings:
            print(f"  WARN: {warning}")

# Export dependency graph
with open("dependencies.dot", "w") as f:
    f.write(report.dependency_graph.export_dot())
```

## Best Practices

1. **Organize Includes**: Keep common rules in a dedicated directory
2. **Avoid Circular Dependencies**: Design your rule hierarchy carefully
3. **Use Search Paths**: Configure YARA_INCLUDE_PATH for system-wide includes
4. **Cache Management**: Clear cache when files are modified externally
5. **Parallel Analysis**: Use parallel mode for large rule sets

## Troubleshooting

### Include Not Found
- Check file exists at the expected path
- Verify search paths are configured correctly
- Use absolute paths for testing

### Circular Dependencies
- Use the dependency graph to visualize the cycle
- Refactor common rules into a separate file
- Consider using rule dependencies instead of file includes

### Performance Issues
- Enable parallel processing for large workspaces
- Use caching (enabled by default)
- Limit directory recursion depth if needed
