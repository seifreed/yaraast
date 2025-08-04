"""Performance optimizer for YARA rules."""

import copy

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, HexWildcard, PlainString, RegexString


class StringOptimizer:
    """Optimize YARA strings for better performance."""

    def optimize_rule(self, rule: Rule) -> tuple[Rule, list[str]]:
        """Optimize a rule and return optimized version with list of changes made."""
        optimized_rule = copy.deepcopy(rule)
        changes = []

        for i, string in enumerate(optimized_rule.strings):
            if isinstance(string, HexString):
                optimized, change = self.optimize_hex_string(string)
                if change:
                    optimized_rule.strings[i] = optimized
                    changes.append(f"{string.identifier}: {change}")
            elif isinstance(string, PlainString):
                optimized, change = self.optimize_plain_string(string)
                if change:
                    optimized_rule.strings[i] = optimized
                    changes.append(f"{string.identifier}: {change}")
            elif isinstance(string, RegexString):
                optimized, change = self.optimize_regex_string(string)
                if change:
                    optimized_rule.strings[i] = optimized
                    changes.append(f"{string.identifier}: {change}")

        return optimized_rule, changes

    def optimize_hex_string(self, string: HexString) -> tuple[HexString, str | None]:
        """Optimize hex string for better performance."""
        if not string.tokens:
            return string, None

        optimized = copy.deepcopy(string)

        # Strategy 1: Replace long wildcard sequences with jumps
        new_tokens = []
        consecutive_wildcards = 0

        for token in optimized.tokens:
            if isinstance(token, HexWildcard):
                consecutive_wildcards += 1
            else:
                if consecutive_wildcards >= 4:
                    # Replace 4+ consecutive wildcards with a jump
                    from yaraast.ast.strings import HexJump

                    new_tokens.append(
                        HexJump(
                            min_jump=consecutive_wildcards,
                            max_jump=consecutive_wildcards,
                        )
                    )
                    change = f"Replaced {consecutive_wildcards} consecutive wildcards with jump [4-{consecutive_wildcards}]"
                else:
                    # Keep the wildcards as is
                    for _ in range(consecutive_wildcards):
                        new_tokens.append(HexWildcard())
                consecutive_wildcards = 0
                new_tokens.append(token)

        # Handle trailing wildcards
        if consecutive_wildcards >= 4:
            from yaraast.ast.strings import HexJump

            new_tokens.append(
                HexJump(min_jump=consecutive_wildcards, max_jump=consecutive_wildcards)
            )
            change = f"Replaced {consecutive_wildcards} consecutive wildcards with jump"
        else:
            for _ in range(consecutive_wildcards):
                new_tokens.append(HexWildcard())
            change = None

        if len(new_tokens) != len(optimized.tokens):
            optimized.tokens = new_tokens
            return optimized, change or "Optimized wildcard patterns"

        return string, None

    def optimize_plain_string(self, string: PlainString) -> tuple[PlainString, str | None]:
        """Optimize plain string for better performance."""
        # Very short strings can't really be optimized
        if len(string.value) <= 2:
            # Could suggest removing or combining with other patterns
            return string, None

        # Strings with only whitespace could be converted to hex patterns
        if all(c in " \t\n\r\x00" for c in string.value):
            # Convert to hex string for better control
            from yaraast.ast.strings import HexByte, HexString

            hex_tokens = []
            for c in string.value:
                hex_tokens.append(HexByte(value=ord(c)))

            HexString(
                identifier=string.identifier,
                tokens=hex_tokens,
                modifiers=string.modifiers,
            )
            return string, None  # For now, don't auto-convert

        return string, None

    def optimize_regex_string(self, string: RegexString) -> tuple[RegexString, str | None]:
        """Optimize regex string for better performance."""
        optimized = copy.deepcopy(string)

        # Remove unnecessary anchors with .*
        if optimized.regex.startswith("^.*"):
            optimized.regex = optimized.regex[3:]
            return optimized, "Removed unnecessary ^.* anchor"

        if optimized.regex.endswith(".*$"):
            optimized.regex = optimized.regex[:-3]
            return optimized, "Removed unnecessary .*$ anchor"

        # Warn about catastrophic backtracking patterns but don't auto-fix
        # as they might be intentional
        problematic = [
            ("(.+)+", "nested quantifiers"),
            ("(.*)*", "nested quantifiers"),
            ("(.+)*", "nested quantifiers"),
            ("(.*)+", "nested quantifiers"),
        ]

        for pattern, _issue in problematic:
            if pattern in optimized.regex:
                # Don't auto-fix as it might break the pattern
                return string, None

        return string, None


def optimize_yara_file(yara_file: YaraFile) -> tuple[YaraFile, list[str]]:
    """Optimize an entire YARA file."""
    optimizer = StringOptimizer()
    optimized_file = copy.deepcopy(yara_file)
    all_changes = []

    for i, rule in enumerate(optimized_file.rules):
        optimized_rule, changes = optimizer.optimize_rule(rule)
        if changes:
            optimized_file.rules[i] = optimized_rule
            for change in changes:
                all_changes.append(f"{rule.name}/{change}")

    return optimized_file, all_changes
