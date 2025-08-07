"""Tests for YARA-L parser."""

import pytest

from yaraast.yaral.ast_nodes import AggregationFunction
from yaraast.yaral.parser import YaraLParser, YaraLParserError


class TestYaraLParser:
    """Test YARA-L parser functionality."""

    def test_basic_rule_structure(self) -> None:
        """Test parsing basic YARA-L rule structure."""
        yaral_code = """
        rule basic_detection {
            meta:
                author = "Security Team"
                severity = "Medium"

            events:
                $e.metadata.event_type = "USER_LOGIN"

            condition:
                #e > 5
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        rule = ast.rules[0]
        assert rule.name == "basic_detection"
        assert rule.meta is not None
        assert len(rule.meta.entries) == 2
        assert rule.events is not None
        assert rule.condition is not None

    def test_events_section(self) -> None:
        """Test parsing events section with UDM fields."""
        yaral_code = """
        rule event_detection {
            events:
                $e1.metadata.event_type = "PROCESS_LAUNCH"
                $e1.principal.hostname = $hostname
                $e1.target.process.file.full_path = "/usr/bin/ssh"
                $e2.metadata.event_type = "NETWORK_CONNECTION"
                $e2.principal.ip in %suspicious_ips%
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.events is not None
        assert len(rule.events.statements) >= 4

        # Check first event statement
        stmt1 = rule.events.statements[0]
        assert stmt1.event_var.name == "$e1"
        assert stmt1.field_path.path == "metadata.event_type"
        assert stmt1.operator == "="
        assert stmt1.value == "PROCESS_LAUNCH"

    def test_match_section_with_time_windows(self) -> None:
        """Test parsing match section with time windows."""
        yaral_code = """
        rule time_window_rule {
            events:
                $e.metadata.event_type = "LOGIN"

            match:
                $hostname over 5m
                $userid over 1h
                $process over every 24h

            condition:
                #e > 10
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.match is not None
        assert len(rule.match.variables) == 3

        # Check first match variable
        var1 = rule.match.variables[0]
        assert var1.variable == "hostname"
        assert var1.time_window.duration == 5
        assert var1.time_window.unit == "m"
        assert var1.time_window.modifier is None

        # Check third match variable with 'every' modifier
        var3 = rule.match.variables[2]
        assert var3.variable == "process"
        assert var3.time_window.duration == 24
        assert var3.time_window.unit == "h"
        assert var3.time_window.modifier == "every"

    def test_condition_expressions(self) -> None:
        """Test parsing various condition expressions."""
        yaral_code = """
        rule complex_condition {
            events:
                $e1.metadata.event_type = "LOGIN"
                $e2.metadata.event_type = "LOGOUT"

            condition:
                (#e1 > 5 and #e2 > 3) or ($e1 and not $e2)
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.condition is not None
        # The condition should be parsed into a binary OR expression
        assert rule.condition.expression is not None

    def test_outcome_section_with_aggregations(self) -> None:
        """Test parsing outcome section with aggregation functions."""
        yaral_code = """
        rule outcome_rule {
            events:
                $e.metadata.event_type = "FILE_ACCESS"

            outcome:
                $total_events = count($e.metadata.id)
                $unique_hosts = count_distinct($e.principal.hostname)
                $max_bytes = max($e.network.sent_bytes)
                $all_ips = array($e.principal.ip)
                $first_seen = earliest($e.metadata.event_timestamp)

            condition:
                $total_events > 100
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None
        assert len(rule.outcome.assignments) == 5

        # Check first outcome assignment
        assign1 = rule.outcome.assignments[0]
        assert assign1.variable == "$total_events"
        assert isinstance(assign1.expression, AggregationFunction)
        assert assign1.expression.function == "count"

    def test_reference_lists_and_cidr(self) -> None:
        """Test parsing reference lists and CIDR expressions."""
        yaral_code = """
        rule reference_list_rule {
            events:
                $e.principal.ip in %blocked_ips%
                $e.network.dns.questions.name in %malicious_domains%
                not ($e.principal.user.userid in %trusted_users%)
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.events is not None
        # Should have parsed reference list statements
        assert len(rule.events.statements) >= 2

    def test_regex_patterns(self) -> None:
        """Test parsing regex patterns in events."""
        yaral_code = r"""
        rule regex_rule {
            events:
                $e.network.dns.questions.name = /.*malicious\.com/ nocase
                $e.principal.hostname = /^server-[0-9]+$/
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.events is not None
        # Check that regex patterns are parsed
        assert len(rule.events.statements) >= 1

        # Check nocase modifier
        stmt1 = rule.events.statements[0]
        assert "nocase" in stmt1.modifiers

    def test_conditional_outcome(self) -> None:
        """Test parsing conditional expressions in outcome."""
        yaral_code = """
        rule conditional_outcome {
            events:
                $e.metadata.event_type = "LOGIN"

            outcome:
                $severity = if($event_count > 100, "HIGH", if($event_count > 50, "MEDIUM", "LOW"))

            condition:
                #e > 0
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.outcome is not None
        assert len(rule.outcome.assignments) == 1

    def test_multi_event_correlation(self) -> None:
        """Test parsing rules with multiple correlated events."""
        yaral_code = """
        rule multi_event {
            events:
                $create.metadata.event_type = "PROCESS_LAUNCH"
                $delete.metadata.event_type = "PROCESS_TERMINATION"
                $create.principal.user.userid = $delete.principal.user.userid
                $create.target.process.pid = $delete.target.process.pid

            match:
                $userid over 10m

            condition:
                $create and $delete
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.events is not None
        assert rule.match is not None
        assert rule.condition is not None

        # Should have multiple event statements
        assert len(rule.events.statements) >= 4

    def test_udm_additional_fields(self) -> None:
        """Test parsing UDM additional fields with map access."""
        yaral_code = """
        rule udm_additional {
            events:
                $e.udm.additional.fields["pod_name"] = "kube-scheduler"
                $e.labels["environment"] = "production"
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        rule = ast.rules[0]
        assert rule.events is not None
        # Check that map access is parsed correctly
        assert len(rule.events.statements) >= 1

    def test_error_handling(self) -> None:
        """Test parser error handling."""
        # Missing colon after section
        yaral_code = """
        rule invalid_rule {
            events
                $e.metadata.event_type = "LOGIN"
        }
        """

        parser = YaraLParser(yaral_code)
        with pytest.raises(YaraLParserError):
            parser.parse()

    def test_empty_rule(self) -> None:
        """Test parsing empty rule."""
        yaral_code = """
        rule empty_rule {
        }
        """

        parser = YaraLParser(yaral_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        rule = ast.rules[0]
        assert rule.name == "empty_rule"
        assert rule.meta is None
        assert rule.events is None
        assert rule.condition is None


class TestYaraLDialectDetection:
    """Test YARA-L dialect detection."""

    def test_detect_yaral_dialect(self) -> None:
        """Test detection of YARA-L dialect."""
        from yaraast.dialects import YaraDialect, detect_dialect

        yaral_code = """
        rule yaral_rule {
            events:
                $e.metadata.event_type = "LOGIN"
            match:
                $hostname over 5m
            condition:
                #e > 5
        }
        """

        dialect = detect_dialect(yaral_code)
        assert dialect == YaraDialect.YARA_L

    def test_detect_standard_yara(self) -> None:
        """Test detection of standard YARA."""
        from yaraast.dialects import YaraDialect, detect_dialect

        yara_code = """
        rule standard_yara {
            meta:
                author = "test"
            strings:
                $a = "malware"
            condition:
                $a
        }
        """

        dialect = detect_dialect(yara_code)
        assert dialect == YaraDialect.YARA

    def test_unified_parser_with_yaral(self) -> None:
        """Test unified parser with YARA-L content."""
        from yaraast.dialects import YaraDialect
        from yaraast.unified_parser import UnifiedParser

        yaral_code = """
        rule unified_test {
            events:
                $e.metadata.event_type = "LOGIN"
            condition:
                #e > 0
        }
        """

        parser = UnifiedParser(yaral_code)
        assert parser.get_dialect() == YaraDialect.YARA_L

        ast = parser.parse()
        assert ast is not None
        assert len(ast.rules) == 1
