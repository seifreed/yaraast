"""Main rule analyzer combining various analysis tools."""

from typing import Any, Dict, List, Optional

from yaraast.analysis.dependency_analyzer import DependencyAnalyzer
from yaraast.analysis.string_usage import StringUsageAnalyzer
from yaraast.ast import YaraFile


class RuleAnalyzer:
    """Comprehensive analyzer for YARA rules."""

    def __init__(self):
        self.string_analyzer = StringUsageAnalyzer()
        self.dependency_analyzer = DependencyAnalyzer()

    def analyze(self, yara_file: YaraFile) -> Dict[str, Any]:
        """Perform comprehensive analysis of YARA file."""
        # Run individual analyses
        string_analysis = self.string_analyzer.analyze(yara_file)
        dependency_analysis = self.dependency_analyzer.analyze(yara_file)

        # Combine results
        results = {
            "summary": self._generate_summary(yara_file, string_analysis, dependency_analysis),
            "string_analysis": string_analysis,
            "dependency_analysis": dependency_analysis,
            "quality_metrics": self._calculate_quality_metrics(string_analysis, dependency_analysis),
            "recommendations": self._generate_recommendations(string_analysis, dependency_analysis)
        }

        return results

    def _generate_summary(self, yara_file: YaraFile, string_analysis: Dict, dependency_analysis: Dict) -> Dict[str, Any]:
        """Generate summary statistics."""
        total_rules = len(yara_file.rules)
        total_strings = sum(len(rule.strings) for rule in yara_file.rules)

        # Count unused strings
        total_unused = 0
        for rule_analysis in string_analysis.values():
            total_unused += len(rule_analysis.get("unused", []))

        # Count rules with dependencies
        rules_with_deps = sum(1 for deps in dependency_analysis["dependencies"].values() if deps)

        return {
            "total_rules": total_rules,
            "total_strings": total_strings,
            "total_unused_strings": total_unused,
            "rules_with_dependencies": rules_with_deps,
            "imported_modules": len(dependency_analysis["imported_modules"]),
            "included_files": len(dependency_analysis["included_files"]),
            "circular_dependencies": len(dependency_analysis["circular_dependencies"])
        }

    def _calculate_quality_metrics(self, string_analysis: Dict, dependency_analysis: Dict) -> Dict[str, Any]:
        """Calculate quality metrics for the rules."""
        metrics = {}

        # String usage efficiency
        total_defined = 0
        total_used = 0
        for rule_data in string_analysis.values():
            total_defined += len(rule_data["defined"])
            total_used += len(rule_data["used"])

        metrics["string_usage_efficiency"] = total_used / total_defined if total_defined > 0 else 0

        # Dependency complexity
        dep_counts = [len(deps) for deps in dependency_analysis["dependencies"].values()]
        metrics["average_dependencies"] = sum(dep_counts) / len(dep_counts) if dep_counts else 0
        metrics["max_dependencies"] = max(dep_counts) if dep_counts else 0

        # Rule independence
        independent_rules = sum(1 for info in dependency_analysis["dependency_graph"].values()
                              if info["is_independent"])
        total_rules = len(dependency_analysis["rules"])
        metrics["independence_ratio"] = independent_rules / total_rules if total_rules > 0 else 0

        # Circular dependency score (lower is better)
        metrics["circular_dependency_score"] = len(dependency_analysis["circular_dependencies"])

        # Overall quality score (0-100)
        quality_score = 100
        quality_score -= (1 - metrics["string_usage_efficiency"]) * 20  # Up to -20 for unused strings
        quality_score -= metrics["circular_dependency_score"] * 10      # -10 per circular dependency
        quality_score -= max(0, metrics["average_dependencies"] - 3) * 5  # Penalty for too many deps

        metrics["overall_quality_score"] = max(0, min(100, quality_score))

        return metrics

    def _generate_recommendations(self, string_analysis: Dict, dependency_analysis: Dict) -> List[Dict[str, str]]:
        """Generate recommendations for improving the rules."""
        recommendations = []

        # Check for unused strings
        unused_by_rule = self.string_analyzer.get_unused_strings()
        if unused_by_rule:
            for rule, strings in unused_by_rule.items():
                recommendations.append({
                    "type": "unused_strings",
                    "severity": "warning",
                    "rule": rule,
                    "message": f"Rule '{rule}' has {len(strings)} unused string(s): {', '.join(strings)}",
                    "suggestion": "Consider removing unused strings or updating the condition to use them"
                })

        # Check for undefined strings
        undefined_by_rule = self.string_analyzer.get_undefined_strings()
        if undefined_by_rule:
            for rule, strings in undefined_by_rule.items():
                recommendations.append({
                    "type": "undefined_strings",
                    "severity": "error",
                    "rule": rule,
                    "message": f"Rule '{rule}' references undefined string(s): {', '.join(strings)}",
                    "suggestion": "Define the missing strings or fix the string identifiers"
                })

        # Check for circular dependencies
        circular_deps = dependency_analysis["circular_dependencies"]
        if circular_deps:
            for cycle in circular_deps:
                recommendations.append({
                    "type": "circular_dependency",
                    "severity": "error",
                    "rule": cycle[0],
                    "message": f"Circular dependency detected: {' -> '.join(cycle)}",
                    "suggestion": "Refactor rules to eliminate circular dependencies"
                })

        # Check for highly dependent rules
        for rule, info in dependency_analysis["dependency_graph"].items():
            dep_count = len(info["depends_on"])
            if dep_count > 5:
                recommendations.append({
                    "type": "high_dependency",
                    "severity": "warning",
                    "rule": rule,
                    "message": f"Rule '{rule}' has {dep_count} dependencies, which may make it fragile",
                    "suggestion": "Consider breaking down the rule or reducing dependencies"
                })

        # Check for low string usage
        for rule, analysis in string_analysis.items():
            usage_rate = analysis["usage_rate"]
            if usage_rate < 0.5 and len(analysis["defined"]) > 2:
                recommendations.append({
                    "type": "low_string_usage",
                    "severity": "info",
                    "rule": rule,
                    "message": f"Rule '{rule}' only uses {usage_rate:.0%} of its defined strings",
                    "suggestion": "Review if all strings are necessary for the rule's purpose"
                })

        return recommendations

    def get_rule_report(self, rule_name: str, yara_file: YaraFile) -> Optional[Dict[str, Any]]:
        """Get detailed report for a specific rule."""
        # Find the rule
        rule = None
        for r in yara_file.rules:
            if r.name == rule_name:
                rule = r
                break

        if not rule:
            return None

        # Analyze just this file
        full_analysis = self.analyze(yara_file)

        # Extract rule-specific data
        report = {
            "name": rule_name,
            "tags": rule.tags,
            "string_count": len(rule.strings),
            "string_usage": full_analysis["string_analysis"].get(rule_name, {}),
            "dependencies": self.dependency_analyzer.get_dependencies(rule_name),
            "dependents": self.dependency_analyzer.get_dependents(rule_name),
            "transitive_dependencies": list(self.dependency_analyzer.get_transitive_dependencies(rule_name)),
            "recommendations": [r for r in full_analysis["recommendations"] if r.get("rule") == rule_name]
        }

        return report
