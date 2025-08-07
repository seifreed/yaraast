"""String pattern diagrams for YARA AST analysis."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

import graphviz

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class StringDiagramGenerator(ASTVisitor[None]):
    """Generates string pattern analysis diagrams."""

    def __init__(self) -> None:
        self.string_patterns: dict[str, dict[str, Any]] = {}
        self.pattern_relationships: dict[str, set[str]] = defaultdict(set)
        self.pattern_stats: dict[str, Any] = {}
        self._current_rule: str | None = None

    def generate_pattern_flow_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate string pattern flow diagram."""
        self._analyze_patterns(ast)

        dot = graphviz.Digraph(comment="YARA String Pattern Flow", engine="dot")
        dot.attr(rankdir="TB", bgcolor="white", fontname="Arial", fontsize="12")
        dot.attr("node", fontname="Arial", fontsize="10")
        dot.attr("edge", fontname="Arial", fontsize="9")

        # Create clusters for different pattern types
        with dot.subgraph(name="cluster_plain") as plain_cluster:
            plain_cluster.attr(
                label="Plain String Patterns",
                style="filled",
                fillcolor="lightblue",
                color="blue",
            )
            plain_cluster.attr(
                "node",
                shape="box",
                style="rounded,filled",
                fillcolor="lightcyan",
            )

            for pattern_id, pattern_info in self.string_patterns.items():
                if pattern_info["type"] == "plain":
                    label = self._create_pattern_label(pattern_info)
                    plain_cluster.node(pattern_id, label)

        with dot.subgraph(name="cluster_hex") as hex_cluster:
            hex_cluster.attr(
                label="Hex Patterns",
                style="filled",
                fillcolor="lightyellow",
                color="orange",
            )
            hex_cluster.attr(
                "node",
                shape="hexagon",
                style="filled",
                fillcolor="yellow",
            )

            for pattern_id, pattern_info in self.string_patterns.items():
                if pattern_info["type"] == "hex":
                    label = self._create_hex_pattern_label(pattern_info)
                    hex_cluster.node(pattern_id, label)

        with dot.subgraph(name="cluster_regex") as regex_cluster:
            regex_cluster.attr(
                label="Regex Patterns",
                style="filled",
                fillcolor="lightgreen",
                color="green",
            )
            regex_cluster.attr(
                "node",
                shape="ellipse",
                style="filled",
                fillcolor="lightgreen",
            )

            for pattern_id, pattern_info in self.string_patterns.items():
                if pattern_info["type"] == "regex":
                    label = self._create_regex_pattern_label(pattern_info)
                    regex_cluster.node(pattern_id, label)

        # Add relationships between patterns
        self._add_pattern_relationships(dot)

        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def generate_pattern_complexity_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate pattern complexity visualization."""
        self._analyze_patterns(ast)

        dot = graphviz.Digraph(comment="YARA Pattern Complexity", engine="neato")
        dot.attr(bgcolor="white", fontname="Arial", overlap="false", splines="true")

        # Position nodes based on complexity
        for pattern_id, pattern_info in self.string_patterns.items():
            complexity = self._calculate_pattern_complexity(pattern_info)

            # Color by complexity
            if complexity <= 3:
                color = "lightgreen"
            elif complexity <= 6:
                color = "yellow"
            else:
                color = "lightcoral"

            # Size by length/tokens
            size = min(2.0, 0.5 + (pattern_info.get("length", 0) / 50))

            label = f"{pattern_info['identifier']}\\nComplexity: {complexity}"
            if pattern_info["type"] == "hex":
                label += f"\\nTokens: {pattern_info.get('tokens', 0)}"

            dot.node(
                pattern_id,
                label,
                style="filled",
                fillcolor=color,
                width=str(size),
                height=str(size),
                shape=self._get_pattern_shape(pattern_info["type"]),
            )

        # Add complexity legend
        with dot.subgraph(name="cluster_legend") as legend:
            legend.attr(label="Complexity Legend", style="filled", fillcolor="white")
            legend.node("low_c", "Low (≤3)", fillcolor="lightgreen", shape="circle")
            legend.node("med_c", "Medium (4-6)", fillcolor="yellow", shape="circle")
            legend.node("high_c", "High (>6)", fillcolor="lightcoral", shape="circle")

        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def generate_pattern_similarity_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate pattern similarity clustering diagram."""
        self._analyze_patterns(ast)

        dot = graphviz.Digraph(comment="YARA Pattern Similarity", engine="fdp")
        dot.attr(bgcolor="white", fontname="Arial", overlap="scale", sep="+20")

        # Group similar patterns
        similarity_groups = self._find_similar_patterns()

        colors = [
            "lightblue",
            "lightgreen",
            "lightyellow",
            "lightcoral",
            "lightpink",
            "lightgray",
            "lightcyan",
            "wheat",
        ]

        for i, (group_type, patterns) in enumerate(similarity_groups.items()):
            color = colors[i % len(colors)]

            with dot.subgraph(name=f"cluster_{i}") as cluster:
                cluster.attr(
                    label=f"{group_type} Patterns",
                    style="filled",
                    fillcolor=color,
                    alpha="0.5",
                )

                for pattern_id in patterns:
                    pattern_info = self.string_patterns[pattern_id]
                    label = self._create_short_label(pattern_info)
                    cluster.node(pattern_id, label, style="filled", fillcolor="white")

                # Connect similar patterns within group
                pattern_list = list(patterns)
                for j in range(len(pattern_list)):
                    for k in range(j + 1, len(pattern_list)):
                        similarity = self._calculate_similarity(
                            self.string_patterns[pattern_list[j]],
                            self.string_patterns[pattern_list[k]],
                        )
                        if similarity > 0.5:
                            dot.edge(
                                pattern_list[j],
                                pattern_list[k],
                                label=f"{similarity:.2f}",
                                style="dashed",
                                color="gray",
                            )

        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def generate_hex_pattern_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate detailed hex pattern analysis diagram."""
        self._analyze_patterns(ast)

        dot = graphviz.Digraph(comment="YARA Hex Pattern Analysis", engine="dot")
        dot.attr(rankdir="LR", bgcolor="white", fontname="Arial")

        hex_patterns = {
            pid: info for pid, info in self.string_patterns.items() if info["type"] == "hex"
        }

        if not hex_patterns:
            # Create empty diagram
            dot.node(
                "no_hex",
                "No Hex Patterns Found",
                shape="box",
                style="filled",
                fillcolor="lightgray",
            )

            if output_path:
                output_file = str(Path(output_path).with_suffix(""))
                dot.render(output_file, format=format, cleanup=True)
                return f"{output_file}.{format}"
            return dot.source

        # Analyze hex token patterns
        for pattern_id, pattern_info in hex_patterns.items():
            tokens = pattern_info.get("token_analysis", {})

            # Create main pattern node
            main_label = f"{pattern_info['identifier']}\\nRule: {pattern_info['rule']}"
            dot.node(
                pattern_id,
                main_label,
                shape="box",
                style="filled",
                fillcolor="lightblue",
            )

            # Create token breakdown
            if tokens:
                token_id = f"{pattern_id}_tokens"
                token_label = self._create_hex_token_label(tokens)
                dot.node(
                    token_id,
                    token_label,
                    shape="record",
                    style="filled",
                    fillcolor="lightyellow",
                )
                dot.edge(pattern_id, token_id, label="tokens")

                # Add complexity metrics
                complexity_id = f"{pattern_id}_complexity"
                complexity_label = self._create_hex_complexity_label(
                    pattern_info,
                    tokens,
                )
                dot.node(
                    complexity_id,
                    complexity_label,
                    shape="note",
                    style="filled",
                    fillcolor="lightgreen",
                )
                dot.edge(pattern_id, complexity_id, label="metrics")

        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def get_pattern_statistics(self) -> dict[str, Any]:
        """Get comprehensive pattern statistics."""
        if not self.string_patterns:
            return {"total_patterns": 0}

        return {
            "total_patterns": len(self.string_patterns),
            "by_type": {
                "plain": len(
                    [p for p in self.string_patterns.values() if p["type"] == "plain"],
                ),
                "hex": len(
                    [p for p in self.string_patterns.values() if p["type"] == "hex"],
                ),
                "regex": len(
                    [p for p in self.string_patterns.values() if p["type"] == "regex"],
                ),
            },
            "complexity_distribution": self._get_complexity_distribution(),
            "common_patterns": self._find_common_patterns(),
            "pattern_lengths": self._get_length_statistics(),
            "modifiers_usage": self._get_modifier_statistics(),
        }

    def _analyze_patterns(self, ast: YaraFile) -> None:
        """Analyze all string patterns in the AST."""
        self.string_patterns.clear()
        self.pattern_relationships.clear()
        self.pattern_stats.clear()

        pattern_id = 0
        for rule in ast.rules:
            self._current_rule = rule.name

            for string_def in rule.strings:
                pattern_id += 1
                pid = f"pattern_{pattern_id}"

                pattern_info: dict[str, Any] = {
                    "id": pid,
                    "identifier": string_def.identifier,
                    "rule": rule.name,
                    "modifiers": [mod.name for mod in string_def.modifiers],
                }

                if isinstance(string_def, PlainString):
                    pattern_info.update(
                        {
                            "type": "plain",
                            "value": string_def.value,
                            "length": len(string_def.value),
                            "printable_ratio": self._calculate_printable_ratio(
                                string_def.value,
                            ),
                        },
                    )

                elif isinstance(string_def, HexString):
                    token_analysis = self._analyze_hex_tokens(string_def.tokens)
                    pattern_info.update(
                        {
                            "type": "hex",
                            "tokens": len(string_def.tokens),
                            "token_analysis": token_analysis,
                            "length": len(string_def.tokens),
                        },
                    )

                elif isinstance(string_def, RegexString):
                    regex_analysis = self._analyze_regex_pattern(string_def.regex)
                    pattern_info.update(
                        {
                            "type": "regex",
                            "pattern": string_def.regex,
                            "regex_analysis": regex_analysis,
                            "length": len(string_def.regex),
                        },
                    )

                self.string_patterns[pid] = pattern_info

    def _analyze_hex_tokens(self, tokens: list) -> dict[str, Any]:
        """Analyze hex string tokens."""
        from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexWildcard

        analysis = {
            "bytes": 0,
            "wildcards": 0,
            "jumps": 0,
            "alternatives": 0,
            "wildcard_ratio": 0.0,
            "complexity_score": 0,
        }

        for token in tokens:
            if isinstance(token, HexByte):
                analysis["bytes"] += 1
            elif isinstance(token, HexWildcard):
                analysis["wildcards"] += 1
            elif isinstance(token, HexJump):
                analysis["jumps"] += 1
                analysis["complexity_score"] += 2
            elif isinstance(token, HexAlternative):
                analysis["alternatives"] += 1
                analysis["complexity_score"] += 3

        total_tokens = len(tokens)
        if total_tokens > 0:
            analysis["wildcard_ratio"] = analysis["wildcards"] / total_tokens

        analysis["complexity_score"] += analysis["wildcards"] * 0.5

        return analysis

    def _analyze_regex_pattern(self, pattern: str) -> dict[str, Any]:
        """Analyze regex pattern complexity."""
        analysis = {
            "groups": len(re.findall(r"\([^?]", pattern)),
            "quantifiers": len(re.findall(r"[*+?{]", pattern)),
            "anchors": len(re.findall(r"[\^$]", pattern)),
            "character_classes": len(re.findall(r"\[[^\]]+\]", pattern)),
            "complexity_score": 0,
        }

        # Calculate complexity score
        analysis["complexity_score"] = (
            analysis["groups"] * 2
            + analysis["quantifiers"]
            + analysis["character_classes"] * 1.5
            + analysis["anchors"] * 0.5
        )

        return analysis

    def _calculate_printable_ratio(self, text: str) -> float:
        """Calculate ratio of printable characters."""
        if not text:
            return 0.0

        printable_count = sum(1 for c in text if c.isprintable() and not c.isspace())
        return printable_count / len(text)

    def _calculate_pattern_complexity(self, pattern_info: dict[str, Any]) -> int:
        """Calculate overall pattern complexity score."""
        complexity = 1  # Base complexity

        if pattern_info["type"] == "plain":
            # Plain string complexity based on length and printability
            length = pattern_info.get("length", 0)
            printable_ratio = pattern_info.get("printable_ratio", 1.0)

            complexity += length // 10  # Length factor
            if printable_ratio < 0.8:
                complexity += 2  # Non-printable penalty

        elif pattern_info["type"] == "hex":
            # Hex complexity from token analysis
            token_analysis = pattern_info.get("token_analysis", {})
            complexity += int(token_analysis.get("complexity_score", 0))

        elif pattern_info["type"] == "regex":
            # Regex complexity from analysis
            regex_analysis = pattern_info.get("regex_analysis", {})
            complexity += int(regex_analysis.get("complexity_score", 0))

        # Modifier complexity
        complexity += len(pattern_info.get("modifiers", []))

        return complexity

    def _find_similar_patterns(self) -> dict[str, set[str]]:
        """Find groups of similar patterns."""
        groups = defaultdict(set)

        # Group by type first
        for pattern_id, pattern_info in self.string_patterns.items():
            pattern_type = pattern_info["type"]
            groups[pattern_type].add(pattern_id)

        # Further group by characteristics
        refined_groups = {}

        for group_type, pattern_ids in groups.items():
            if group_type == "plain":
                # Group plain strings by length ranges
                short_patterns = set()
                medium_patterns = set()
                long_patterns = set()

                for pid in pattern_ids:
                    length = self.string_patterns[pid].get("length", 0)
                    if length < 10:
                        short_patterns.add(pid)
                    elif length < 50:
                        medium_patterns.add(pid)
                    else:
                        long_patterns.add(pid)

                if short_patterns:
                    refined_groups["Short Plain"] = short_patterns
                if medium_patterns:
                    refined_groups["Medium Plain"] = medium_patterns
                if long_patterns:
                    refined_groups["Long Plain"] = long_patterns

            elif group_type == "hex":
                # Group hex patterns by wildcard ratio
                low_wildcard = set()
                high_wildcard = set()

                for pid in pattern_ids:
                    token_analysis = self.string_patterns[pid].get("token_analysis", {})
                    wildcard_ratio = token_analysis.get("wildcard_ratio", 0)

                    if wildcard_ratio < 0.3:
                        low_wildcard.add(pid)
                    else:
                        high_wildcard.add(pid)

                if low_wildcard:
                    refined_groups["Precise Hex"] = low_wildcard
                if high_wildcard:
                    refined_groups["Flexible Hex"] = high_wildcard

            else:  # regex
                refined_groups["Regex"] = pattern_ids

        return refined_groups

    def _calculate_similarity(
        self,
        pattern1: dict[str, Any],
        pattern2: dict[str, Any],
    ) -> float:
        """Calculate similarity between two patterns."""
        if pattern1["type"] != pattern2["type"]:
            return 0.0

        similarity = 0.0

        if pattern1["type"] == "plain":
            # Simple string similarity
            str1 = pattern1.get("value", "")
            str2 = pattern2.get("value", "")

            if len(str1) == 0 or len(str2) == 0:
                return 0.0

            # Simple Jaccard similarity on character level
            set1 = set(str1.lower())
            set2 = set(str2.lower())
            intersection = len(set1 & set2)
            union = len(set1 | set2)

            similarity = intersection / union if union > 0 else 0.0

        elif pattern1["type"] == "hex":
            # Compare hex token patterns
            tokens1 = pattern1.get("token_analysis", {})
            tokens2 = pattern2.get("token_analysis", {})

            # Compare wildcard ratios
            ratio1 = tokens1.get("wildcard_ratio", 0)
            ratio2 = tokens2.get("wildcard_ratio", 0)
            similarity = 1.0 - abs(ratio1 - ratio2)

        elif pattern1["type"] == "regex":
            # Simple regex similarity (could be enhanced)
            regex1 = pattern1.get("pattern", "")
            regex2 = pattern2.get("pattern", "")

            if len(regex1) == 0 or len(regex2) == 0:
                return 0.0

            # Character-level similarity
            set1 = set(regex1)
            set2 = set(regex2)
            intersection = len(set1 & set2)
            union = len(set1 | set2)

            similarity = intersection / union if union > 0 else 0.0

        return similarity

    def _create_pattern_label(self, pattern_info: dict[str, Any]) -> str:
        """Create label for plain string pattern."""
        identifier = pattern_info["identifier"]
        value = pattern_info.get("value", "")
        length = pattern_info.get("length", 0)

        # Truncate long values
        display_value = value[:20] + "..." if len(value) > 20 else value

        return f'{identifier}\\n"{display_value}"\\nLength: {length}'

    def _create_hex_pattern_label(self, pattern_info: dict[str, Any]) -> str:
        """Create label for hex pattern."""
        identifier = pattern_info["identifier"]
        tokens = pattern_info.get("tokens", 0)
        token_analysis = pattern_info.get("token_analysis", {})

        wildcards = token_analysis.get("wildcards", 0)
        wildcard_ratio = token_analysis.get("wildcard_ratio", 0)

        return f"{identifier}\\nTokens: {tokens}\\nWildcards: {wildcards} ({wildcard_ratio:.1%})"

    def _create_regex_pattern_label(self, pattern_info: dict[str, Any]) -> str:
        """Create label for regex pattern."""
        identifier = pattern_info["identifier"]
        pattern = pattern_info.get("pattern", "")
        regex_analysis = pattern_info.get("regex_analysis", {})

        # Truncate long patterns
        display_pattern = pattern[:15] + "..." if len(pattern) > 15 else pattern
        groups = regex_analysis.get("groups", 0)

        return f"{identifier}\\n/{display_pattern}/\\nGroups: {groups}"

    def _create_short_label(self, pattern_info: dict[str, Any]) -> str:
        """Create short label for similarity diagram."""
        return pattern_info["identifier"]

    def _create_hex_token_label(self, token_analysis: dict[str, Any]) -> str:
        """Create detailed hex token label."""
        bytes_count = token_analysis.get("bytes", 0)
        wildcards = token_analysis.get("wildcards", 0)
        jumps = token_analysis.get("jumps", 0)
        alternatives = token_analysis.get("alternatives", 0)

        return f"Bytes: {bytes_count}|Wildcards: {wildcards}|Jumps: {jumps}|Alternatives: {alternatives}"

    def _create_hex_complexity_label(
        self,
        pattern_info: dict[str, Any],
        token_analysis: dict[str, Any],
    ) -> str:
        """Create hex complexity metrics label."""
        complexity = self._calculate_pattern_complexity(pattern_info)
        wildcard_ratio = token_analysis.get("wildcard_ratio", 0)
        complexity_score = token_analysis.get("complexity_score", 0)

        return f"Overall Complexity: {complexity}\\nWildcard Ratio: {wildcard_ratio:.1%}\\nToken Score: {complexity_score}"

    def _add_pattern_relationships(self, dot: graphviz.Digraph) -> None:
        """Add relationships between patterns."""
        # Find patterns from same rule
        rule_patterns = defaultdict(list)
        for pattern_id, pattern_info in self.string_patterns.items():
            rule_patterns[pattern_info["rule"]].append(pattern_id)

        # Connect patterns from same rule
        for rule_name, patterns in rule_patterns.items():
            if len(patterns) > 1:
                # Create rule node
                rule_id = f"rule_{rule_name}"
                dot.node(
                    rule_id,
                    f"Rule: {rule_name}",
                    shape="diamond",
                    style="filled",
                    fillcolor="lightgray",
                )

                # Connect all patterns to rule
                for pattern_id in patterns:
                    dot.edge(rule_id, pattern_id, style="dotted", color="gray")

    def _get_complexity_distribution(self) -> dict[str, int]:
        """Get distribution of complexity scores."""
        distribution = {"low": 0, "medium": 0, "high": 0}

        for pattern_info in self.string_patterns.values():
            complexity = self._calculate_pattern_complexity(pattern_info)

            if complexity <= 3:
                distribution["low"] += 1
            elif complexity <= 6:
                distribution["medium"] += 1
            else:
                distribution["high"] += 1

        return distribution

    def _find_common_patterns(self) -> list[tuple[str, int]]:
        """Find most common pattern types/characteristics."""
        common = []

        # Most common modifiers
        modifier_counts = Counter()
        for pattern_info in self.string_patterns.values():
            for modifier in pattern_info.get("modifiers", []):
                modifier_counts[modifier] += 1

        common.extend(
            [("modifier_" + mod, count) for mod, count in modifier_counts.most_common(3)],
        )

        return common

    def _get_length_statistics(self) -> dict[str, float]:
        """Get pattern length statistics."""
        lengths = [pattern_info.get("length", 0) for pattern_info in self.string_patterns.values()]

        if not lengths:
            return {}

        return {
            "min": min(lengths),
            "max": max(lengths),
            "avg": sum(lengths) / len(lengths),
            "median": sorted(lengths)[len(lengths) // 2],
        }

    def _get_modifier_statistics(self) -> dict[str, int]:
        """Get modifier usage statistics."""
        modifier_stats = Counter()

        for pattern_info in self.string_patterns.values():
            for modifier in pattern_info.get("modifiers", []):
                modifier_stats[modifier] += 1

        return dict(modifier_stats)

    # Required visitor methods (minimal implementations)
    def visit_yara_file(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_import(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_include(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_rule(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_tag(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_definition(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_plain_string(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_string(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_regex_string(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_modifier(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_token(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_byte(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_wildcard(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_jump(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_alternative(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_nibble(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_identifier(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_identifier(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_count(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_offset(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_length(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_integer_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_double_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_regex_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_boolean_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_binary_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_unary_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_parentheses_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_set_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_range_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_function_call(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_array_access(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_member_access(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_condition(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_for_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_for_of_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_at_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_in_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_of_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_meta(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_module_reference(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_dictionary_access(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_comment(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_comment_group(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_defined_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_operator_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_extern_import(self, node) -> None:
        """Visit ExternImport node."""
        # Implementation intentionally empty

    def visit_extern_namespace(self, node) -> None:
        """Visit ExternNamespace node."""
        # Implementation intentionally empty

    def visit_extern_rule(self, node) -> None:
        """Visit ExternRule node."""
        # Implementation intentionally empty

    def visit_extern_rule_reference(self, node) -> None:
        """Visit ExternRuleReference node."""
        # Implementation intentionally empty

    def visit_in_rule_pragma(self, node) -> None:
        """Visit InRulePragma node."""
        # Implementation intentionally empty

    def visit_pragma(self, node) -> None:
        """Visit Pragma node."""
        # Implementation intentionally empty

    def visit_pragma_block(self, node) -> None:
        """Visit PragmaBlock node."""
        # Implementation intentionally empty

    def _get_pattern_shape(self, pattern_type: str) -> str:
        """Get shape for pattern type."""
        if pattern_type == "plain":
            return "circle"
        if pattern_type == "hex":
            return "hexagon"
        return "ellipse"

    def generate(self, string_def) -> str:
        """Generate string diagram for a single string definition."""
        if isinstance(string_def, PlainString):
            return self._generate_plain_diagram(string_def)
        if isinstance(string_def, HexString):
            return self._generate_hex_diagram(string_def)
        if isinstance(string_def, RegexString):
            return self._generate_regex_diagram(string_def)
        return f"Unknown string type: {type(string_def).__name__}"

    def _generate_plain_diagram(self, string_def: PlainString) -> str:
        """Generate diagram for plain string."""
        diagram = f"PlainString: {string_def.identifier}\n"
        diagram += f'Value: "{string_def.value}"\n'
        diagram += f"Length: {len(string_def.value)}\n"

        if string_def.modifiers:
            # Handle both string and object modifiers
            mod_names = []
            for mod in string_def.modifiers:
                if hasattr(mod, "name"):
                    mod_names.append(mod.name)
                else:
                    mod_names.append(str(mod))
            modifiers = ", ".join(mod_names)
            diagram += f"Modifiers: {modifiers}\n"

        return diagram

    def _generate_hex_diagram(self, string_def: HexString) -> str:
        """Generate diagram for hex string."""
        from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexWildcard

        diagram = f"HexString: {string_def.identifier}\n"
        diagram += "Pattern: { "

        pattern_parts = []
        for token in string_def.tokens:
            if isinstance(token, HexByte):
                pattern_parts.append(f"{token.value:02X}")
            elif isinstance(token, HexWildcard):
                pattern_parts.append("??")
            elif isinstance(token, HexJump):
                if token.min_jump == token.max_jump:
                    pattern_parts.append(f"[{token.min_jump}]")
                else:
                    pattern_parts.append(f"[{token.min_jump}-{token.max_jump}]")
            elif isinstance(token, HexAlternative):
                alt_str = "|".join(f"{b:02X}" for b in token.alternatives)
                pattern_parts.append(f"({alt_str})")

        diagram += " ".join(pattern_parts) + " }\n"

        if string_def.modifiers:
            # Handle both string and object modifiers
            mod_names = []
            for mod in string_def.modifiers:
                if hasattr(mod, "name"):
                    mod_names.append(mod.name)
                else:
                    mod_names.append(str(mod))
            modifiers = ", ".join(mod_names)
            diagram += f"Modifiers: {modifiers}\n"

        return diagram

    def _generate_regex_diagram(self, string_def: RegexString) -> str:
        """Generate diagram for regex string."""
        diagram = f"RegexString: {string_def.identifier}\n"
        diagram += f"Pattern: /{string_def.regex}/\n"

        # Simple regex analysis
        groups = len(re.findall(r"\([^?]", string_def.regex))
        quantifiers = len(re.findall(r"[*+?{]", string_def.regex))

        if groups > 0:
            diagram += f"Capture Groups: {groups}\n"
        if quantifiers > 0:
            diagram += f"Quantifiers: {quantifiers}\n"

        if string_def.modifiers:
            # Handle both string and object modifiers
            mod_names = []
            for mod in string_def.modifiers:
                if hasattr(mod, "name"):
                    mod_names.append(mod.name)
                else:
                    mod_names.append(str(mod))
            modifiers = ", ".join(mod_names)
            diagram += f"Modifiers: {modifiers}\n"

        return diagram


# Convenience functions
def generate_string_diagram(string_def) -> str:
    """Generate string diagram for a string definition."""
    gen = StringDiagramGenerator()
    return gen.generate(string_def)


def create_hex_diagram(tokens: list) -> str:
    """Create hex pattern diagram from tokens."""
    from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexWildcard

    pattern_parts = []
    for token in tokens:
        if isinstance(token, HexByte):
            pattern_parts.append(f"{token.value:02X}")
        elif isinstance(token, HexWildcard):
            pattern_parts.append("??")
        elif isinstance(token, HexJump):
            if token.min_jump == token.max_jump:
                pattern_parts.append(f"[{token.min_jump}]")
            else:
                pattern_parts.append(f"[{token.min_jump}-{token.max_jump}]")
        elif isinstance(token, HexAlternative):
            alt_str = "|".join(f"{b:02X}" for b in token.alternatives)
            pattern_parts.append(f"({alt_str})")

    return " ".join(pattern_parts)


def create_regex_diagram(pattern: str) -> str:
    """Create regex pattern diagram."""
    groups = re.findall(r"\([^?]", pattern)
    quantifiers = re.findall(r"[*+?{]", pattern)
    anchors = re.findall(r"[\^$]", pattern)
    char_classes = re.findall(r"\[[^\]]+\]", pattern)

    diagram = f"Pattern: /{pattern}/\n"

    if groups:
        diagram += f"Capture groups: {len(groups)}\n"
        diagram += f"  Groups: {groups}\n"

    if quantifiers:
        diagram += f"Quantifiers: {quantifiers}\n"

    if anchors:
        diagram += f"Anchors: {anchors}\n"

    if char_classes:
        diagram += f"Character classes: {char_classes}\n"

    return diagram


def analyze_string_patterns(strings: list) -> dict[str, Any]:
    """Analyze patterns in a list of string definitions."""
    analysis = {
        "total_strings": len(strings),
        "types": {
            "plain": 0,
            "hex": 0,
            "regex": 0,
        },
        "patterns": {
            "common_prefixes": [],
            "common_suffixes": [],
            "duplicates": [],
        },
        "modifiers": {},
    }

    plain_values = []

    for string_def in strings:
        if isinstance(string_def, PlainString):
            analysis["types"]["plain"] += 1
            plain_values.append(string_def.value)
        elif isinstance(string_def, HexString):
            analysis["types"]["hex"] += 1
        elif isinstance(string_def, RegexString):
            analysis["types"]["regex"] += 1

        # Count modifiers
        for mod in string_def.modifiers:
            # Handle both string and object modifiers
            mod_name = mod.name if hasattr(mod, "name") else str(mod)
            analysis["modifiers"][mod_name] = analysis["modifiers"].get(mod_name, 0) + 1

    # Find common prefixes in plain strings
    if len(plain_values) > 1:
        # Find common prefixes
        prefixes = Counter()
        for i, s1 in enumerate(plain_values):
            for _j, s2 in enumerate(plain_values[i + 1 :], i + 1):
                # Find common prefix
                prefix = ""
                for k in range(min(len(s1), len(s2))):
                    if s1[k] == s2[k]:
                        prefix += s1[k]
                    else:
                        break
                if len(prefix) >= 3:  # Minimum prefix length
                    prefixes[prefix] += 1

        analysis["patterns"]["common_prefixes"] = [
            p for p, count in prefixes.most_common(5) if count >= 2
        ]

        # Find duplicates
        value_counts = Counter(plain_values)
        analysis["patterns"]["duplicates"] = [v for v, count in value_counts.items() if count > 1]

    return analysis


def generate_pattern_report(strings: list) -> dict[str, Any]:
    """Generate comprehensive pattern analysis report."""
    analysis = analyze_string_patterns(strings)

    report = {
        "summary": {
            "total": analysis["total_strings"],
            "by_type": analysis["types"],
            "unique_patterns": analysis["total_strings"] - len(analysis["patterns"]["duplicates"]),
        },
        "details": [],
    }

    # Add details for each string
    for string_def in strings:
        detail = {
            "identifier": string_def.identifier,
            "type": type(string_def).__name__,
            "modifiers": [
                mod.name if hasattr(mod, "name") else str(mod) for mod in string_def.modifiers
            ],
        }

        if isinstance(string_def, PlainString):
            detail["value"] = string_def.value
            detail["length"] = len(string_def.value)
        elif isinstance(string_def, HexString):
            detail["tokens"] = len(string_def.tokens)
        elif isinstance(string_def, RegexString):
            detail["pattern"] = string_def.regex

        report["details"].append(detail)

    return report
