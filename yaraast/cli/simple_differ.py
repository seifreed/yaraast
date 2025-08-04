"""Simple but effective AST differ."""

from dataclasses import dataclass, field
from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.codegen import CodeGenerator
from yaraast.parser import Parser


@dataclass
class SimpleDiffResult:
    """Result of AST diff comparison."""

    has_changes: bool = False
    added_rules: list[str] = field(default_factory=list)
    removed_rules: list[str] = field(default_factory=list)
    modified_rules: list[str] = field(default_factory=list)
    added_strings: dict[str, list[str]] = field(default_factory=dict)
    removed_strings: dict[str, list[str]] = field(default_factory=dict)
    condition_changes: dict[str, tuple] = field(default_factory=dict)
    logical_changes: list[str] = field(default_factory=list)
    structural_changes: list[str] = field(default_factory=list)
    style_only_changes: list[str] = field(default_factory=list)
    change_summary: dict[str, int] = field(default_factory=dict)


class SimpleASTDiffer:
    """Simple AST differ that actually detects differences."""

    def diff_files(self, file1_path: Path, file2_path: Path) -> SimpleDiffResult:
        """Compare two YARA files."""
        try:
            # Parse both files
            parser = Parser()

            with file1_path.open() as f:
                content1 = f.read()
                ast1 = parser.parse(content1)

            with file2_path.open() as f:
                content2 = f.read()
                ast2 = parser.parse(content2)

            return self.diff_asts(ast1, ast2, content1, content2)

        except Exception as e:
            result = SimpleDiffResult(has_changes=True)
            result.logical_changes.append(f"Error comparing files: {e}")
            return result

    def diff_asts(
        self, ast1: YaraFile, ast2: YaraFile, content1: str, content2: str
    ) -> SimpleDiffResult:
        """Compare two ASTs."""
        result = SimpleDiffResult()

        # Quick content check first
        if content1.strip() == content2.strip():
            result.has_changes = False
            return result

        # Get rule names
        rules1 = {rule.name: rule for rule in (ast1.rules if ast1 and ast1.rules else [])}
        rules2 = {rule.name: rule for rule in (ast2.rules if ast2 and ast2.rules else [])}

        rules1_names = set(rules1.keys())
        rules2_names = set(rules2.keys())

        # Find added/removed rules
        result.added_rules = list(rules2_names - rules1_names)
        result.removed_rules = list(rules1_names - rules2_names)

        if result.added_rules or result.removed_rules:
            result.has_changes = True

        # Check common rules for modifications
        common_rules = rules1_names & rules2_names
        for rule_name in common_rules:
            rule1 = rules1[rule_name]
            rule2 = rules2[rule_name]

            if self._rules_differ(rule1, rule2):
                result.modified_rules.append(rule_name)
                result.has_changes = True

                # Analyze what changed
                self._analyze_rule_changes(rule1, rule2, rule_name, result)

        # Check imports
        imports1 = {imp.module for imp in (ast1.imports if ast1 and ast1.imports else [])}
        imports2 = {imp.module for imp in (ast2.imports if ast2 and ast2.imports else [])}

        if imports1 != imports2:
            result.has_changes = True
            added_imports = imports2 - imports1
            removed_imports = imports1 - imports2
            if added_imports:
                result.structural_changes.append(f"Added imports: {', '.join(added_imports)}")
            if removed_imports:
                result.structural_changes.append(f"Removed imports: {', '.join(removed_imports)}")

        # Check includes
        includes1 = {inc.path for inc in (ast1.includes if ast1 and ast1.includes else [])}
        includes2 = {inc.path for inc in (ast2.includes if ast2 and ast2.includes else [])}

        if includes1 != includes2:
            result.has_changes = True
            added_includes = includes2 - includes1
            removed_includes = includes1 - includes2
            if added_includes:
                result.structural_changes.append(f"Added includes: {', '.join(added_includes)}")
            if removed_includes:
                result.structural_changes.append(f"Removed includes: {', '.join(removed_includes)}")

        # Update summary
        result.change_summary = {
            "added_rules": len(result.added_rules),
            "removed_rules": len(result.removed_rules),
            "modified_rules": len(result.modified_rules),
            "structural_changes": len(result.structural_changes),
            "logical_changes": len(result.logical_changes),
        }

        return result

    def _rules_differ(self, rule1, rule2) -> bool:
        """Check if two rules are different."""
        # Compare tags
        tags1 = set(rule1.tags) if rule1.tags else set()
        tags2 = set(rule2.tags) if rule2.tags else set()
        if tags1 != tags2:
            return True

        # Compare meta
        meta1 = rule1.meta if rule1.meta else {}
        meta2 = rule2.meta if rule2.meta else {}
        if meta1 != meta2:
            return True

        # Compare strings (by identifier)
        strings1 = {s.identifier: self._string_signature(s) for s in (rule1.strings or [])}
        strings2 = {s.identifier: self._string_signature(s) for s in (rule2.strings or [])}
        if strings1 != strings2:
            return True

        # Compare conditions (simplified - just generate and compare)
        try:
            gen = CodeGenerator()
            cond1 = gen.generate(rule1.condition) if rule1.condition else ""
            cond2 = gen.generate(rule2.condition) if rule2.condition else ""
            if cond1.strip() != cond2.strip():
                return True
        except Exception:
            # If generation fails, assume they're different
            return True

        return False

    def _string_signature(self, string) -> str:
        """Get a signature for a string definition."""
        try:
            gen = CodeGenerator()
            return gen.generate(string).strip()
        except Exception:
            return str(string)

    def _analyze_rule_changes(self, rule1, rule2, rule_name: str, result: SimpleDiffResult):
        """Analyze what changed in a rule."""
        # Check strings
        strings1 = {s.identifier for s in (rule1.strings or [])}
        strings2 = {s.identifier for s in (rule2.strings or [])}

        added_strings = strings2 - strings1
        removed_strings = strings1 - strings2

        if added_strings:
            result.added_strings[rule_name] = list(added_strings)
            result.logical_changes.append(f"Rule '{rule_name}': added strings {added_strings}")

        if removed_strings:
            result.removed_strings[rule_name] = list(removed_strings)
            result.logical_changes.append(f"Rule '{rule_name}': removed strings {removed_strings}")

        # Check condition
        try:
            gen = CodeGenerator()
            cond1 = gen.generate(rule1.condition) if rule1.condition else ""
            cond2 = gen.generate(rule2.condition) if rule2.condition else ""

            if cond1.strip() != cond2.strip():
                result.condition_changes[rule_name] = (cond1.strip(), cond2.strip())
                result.logical_changes.append(f"Rule '{rule_name}': condition changed")
        except Exception:
            pass
