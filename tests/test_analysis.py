"""Test AST-based analysis features."""

from yaraast.analysis import (
    AnalysisReport,
    BestPracticesAnalyzer,
    OptimizationAnalyzer,
    OptimizationReport,
)
from yaraast.parser import Parser


class TestBestPracticesAnalyzer:
    """Test best practices analysis."""

    def test_rule_naming_conventions(self) -> None:
        """Test rule name convention checking."""
        rule_text = """
        rule bad123name { condition: true }
        rule _also_bad { condition: true }
        rule good_name { condition: true }
        rule a { condition: true }  // too short
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = BestPracticesAnalyzer()
        report = analyzer.analyze(ast)

        # Check for naming issues
        warnings = report.get_by_severity("warning")
        assert len(warnings) >= 2  # bad names

        info = report.get_by_severity("info")
        assert any("descriptive" in s.message for s in info)  # short name

    def test_string_naming_conventions(self) -> None:
        """Test string identifier conventions."""
        rule_text = """
        rule test_strings {
            strings:
                $good = "test"
                $123 = "starts with number"
                $a = "ok"
            condition:
                any of them
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = BestPracticesAnalyzer()
        report = analyzer.analyze(ast)

        warnings = report.get_by_severity("warning")
        assert any("$name convention" in s.message for s in warnings)

    def test_section_order_suggestion(self) -> None:
        """Test section order checking."""
        rule_text = """
        rule wrong_order {
            condition:
                true
            strings:
                $a = "test"
            meta:
                author = "test"
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = BestPracticesAnalyzer()
        report = analyzer.analyze(ast)

        info = report.get_by_severity("info")
        assert any("section order" in s.message for s in info)

    def test_unused_strings_detection(self) -> None:
        """Test detection of unused strings."""
        rule_text = """
        rule unused_test {
            strings:
                $used = "test"
                $unused = "never referenced"
            condition:
                $used
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = BestPracticesAnalyzer()
        report = analyzer.analyze(ast)

        warnings = report.get_by_severity("warning")
        assert any("$unused" in s.message and "never used" in s.message for s in warnings)

    def test_short_string_warning(self) -> None:
        """Test warning for very short strings."""
        rule_text = """
        rule short_strings {
            strings:
                $a = "ab"  // too short
                $b = "this is long enough"
            condition:
                all of them
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = BestPracticesAnalyzer()
        report = analyzer.analyze(ast)

        info = report.get_by_severity("info")
        assert any("Short string" in s.message for s in info)

    def test_duplicate_detection(self) -> None:
        """Test detection of duplicate names."""
        rule_text = """
        rule dup_test {
            strings:
                $a = "first"
                $a = "duplicate"
            condition:
                $a
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = BestPracticesAnalyzer()
        report = analyzer.analyze(ast)

        errors = report.get_by_severity("error")
        assert any("Duplicate string identifier" in s.message for s in errors)


class TestOptimizationAnalyzer:
    """Test optimization analysis."""

    def test_hex_pattern_consolidation(self) -> None:
        """Test suggestion for consolidating hex patterns."""
        rule_text = """
        rule hex_patterns {
            strings:
                $a = { 48 65 6c 6c 6f 20 }
                $b = { 48 65 6c 6c 6f 21 }
                $c = { 48 65 6c 6c 6f 3f }
            condition:
                any of them
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = OptimizationAnalyzer()
        report = analyzer.analyze(ast)

        # Should suggest consolidation
        assert any("common prefix" in s.description for s in report.suggestions)

    def test_overlapping_patterns(self) -> None:
        """Test detection of overlapping patterns."""
        rule_text = """
        rule overlapping {
            strings:
                $a = "malicious"
                $b = "malicious code"  // contains $a
            condition:
                all of them
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = OptimizationAnalyzer()
        report = analyzer.analyze(ast)

        # Should detect redundancy
        assert any("contained in" in s.description for s in report.suggestions)

    def test_redundant_comparisons(self) -> None:
        """Test detection of redundant comparisons."""
        rule_text = """
        rule redundant {
            strings:
                $a = "test"
            condition:
                #a > 5 and #a > 10  // second makes first redundant
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = OptimizationAnalyzer()
        report = analyzer.analyze(ast)

        # Should detect redundancy
        assert any("Redundant comparison" in s.description for s in report.suggestions)

    def test_hex_wildcard_optimization(self) -> None:
        """Test warning for excessive wildcards."""
        rule_text = """
        rule wildcards {
            strings:
                $mostly_wildcards = { 48 ?? ?? ?? ?? ?? ?? ?? }
            condition:
                $mostly_wildcards
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = BestPracticesAnalyzer()  # This check is in best practices
        report = analyzer.analyze(ast)

        warnings = report.get_by_severity("warning")
        assert any("wildcards" in s.message and "inefficient" in s.message for s in warnings)

    def test_cross_rule_duplication(self) -> None:
        """Test detection of patterns duplicated across rules."""
        rule_text = """
        rule rule1 {
            strings:
                $a = "same pattern"
            condition: $a
        }

        rule rule2 {
            strings:
                $b = "same pattern"
            condition: $b
        }

        rule rule3 {
            strings:
                $c = "same pattern"
            condition: $c
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = OptimizationAnalyzer()
        report = analyzer.analyze(ast)

        # Should detect duplication
        assert any("Same plain pattern used in" in s.description for s in report.suggestions)

    def test_complex_condition_warning(self) -> None:
        """Test warning for overly complex conditions."""
        # Create deeply nested condition
        rule_text = """
        rule complex {
            condition:
                (true and (false or (true and (false or (true and false)))))
        }
        """

        parser = Parser()
        ast = parser.parse(rule_text)

        analyzer = OptimizationAnalyzer()
        report = analyzer.analyze(ast)

        # Should warn about complexity
        assert any("deep condition nesting" in s.description for s in report.suggestions)


class TestReportFeatures:
    """Test report functionality."""

    def test_analysis_report_categorization(self) -> None:
        """Test report categorization features."""
        report = AnalysisReport()

        report.add_suggestion("rule1", "style", "info", "Style issue")
        report.add_suggestion("rule2", "optimization", "warning", "Optimize this")
        report.add_suggestion("rule3", "structure", "error", "Structure error")

        assert len(report.get_by_severity("info")) == 1
        assert len(report.get_by_severity("warning")) == 1
        assert len(report.get_by_severity("error")) == 1

        assert len(report.get_by_category("style")) == 1
        assert len(report.get_by_category("optimization")) == 1

        assert report.has_issues  # Has warnings/errors

    def test_optimization_report_impact(self) -> None:
        """Test optimization report impact tracking."""
        report = OptimizationReport()

        report.add_suggestion("rule1", "type1", "Low impact", "low")
        report.add_suggestion("rule2", "type2", "Medium impact", "medium")
        report.add_suggestion("rule3", "type3", "High impact", "high")
        report.add_suggestion("rule4", "type3", "Another high", "high")

        assert report.high_impact_count == 2
        assert len(report.suggestions) == 4
