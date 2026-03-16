"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

YARA test file generator for benchmarking.

This module generates realistic YARA rule files of varying sizes
and complexity levels for performance testing.
"""

import random
from pathlib import Path


class YaraTestFileGenerator:
    """Generates realistic YARA test files for benchmarking purposes."""

    def __init__(self, seed: int = 42) -> None:
        """Initialize the generator with a seed for reproducibility.

        Args:
            seed: Random seed for reproducible test file generation
        """
        random.seed(seed)
        self.rule_count = 0

    def generate_identifier(self, prefix: str = "rule") -> str:
        """Generate a unique identifier.

        Args:
            prefix: Prefix for the identifier

        Returns:
            Unique identifier string
        """
        self.rule_count += 1
        return f"{prefix}_{self.rule_count:05d}"

    def generate_meta_section(self) -> str:
        """Generate a realistic meta section.

        Returns:
            YARA meta section string
        """
        authors = ["Security Team", "Threat Intel", "Malware Analyst", "SOC Team"]
        categories = ["malware", "ransomware", "trojan", "backdoor", "exploit"]

        lines = ["    meta:"]
        lines.append(f'        author = "{random.choice(authors)}"')
        lines.append(f'        description = "Detects {random.choice(categories)} behavior"')
        lines.append(f"        version = {random.randint(1, 10)}")
        lines.append(f"        severity = {random.randint(1, 5)}")

        if random.random() > 0.5:
            lines.append(
                f'        reference = "https://example.com/ref{random.randint(1000, 9999)}"'
            )

        if random.random() > 0.7:
            lines.append(
                f'        date = "2025-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"'
            )

        return "\n".join(lines)

    def generate_plain_string(self) -> str:
        """Generate a realistic plain text string.

        Returns:
            YARA plain string definition
        """
        patterns = [
            "This program cannot be run in DOS mode",
            "kernel32.dll",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "RegCreateKey",
            "LoadLibrary",
            "GetProcAddress",
            "WinExec",
            "ShellExecute",
        ]

        modifiers = []
        if random.random() > 0.5:
            modifiers.append("wide")
        if random.random() > 0.6:
            modifiers.append("ascii")
        if random.random() > 0.7:
            modifiers.append("nocase")
        if random.random() > 0.8:
            modifiers.append("fullword")

        modifier_str = " ".join(modifiers)
        if modifier_str:
            modifier_str = " " + modifier_str

        return f'"{random.choice(patterns)}"{modifier_str}'

    def generate_hex_string(self) -> str:
        """Generate a realistic hex string pattern.

        Returns:
            YARA hex string definition
        """
        # Generate hex patterns
        hex_bytes = []
        length = random.randint(4, 20)

        for _ in range(length):
            if random.random() > 0.8:
                # Add wildcard
                hex_bytes.append("??")
            elif random.random() > 0.9:
                # Add nibble wildcard
                choice = random.choice(["?0", "?F", "5?", "A?"])
                hex_bytes.append(choice)
            else:
                # Add normal byte
                hex_bytes.append(f"{random.randint(0, 255):02X}")

        # Add jumps occasionally
        hex_str = " ".join(hex_bytes)
        if random.random() > 0.7:
            insert_pos = random.randint(0, len(hex_bytes) // 2)
            jump_size = random.randint(1, 10)
            hex_list = hex_str.split()
            hex_list.insert(insert_pos, f"[{jump_size}]")
            hex_str = " ".join(hex_list)

        return f"{{ {hex_str} }}"

    def generate_regex_string(self) -> str:
        """Generate a realistic regex pattern.

        Returns:
            YARA regex string definition
        """
        patterns = [
            r"[A-Za-z0-9]{32}",
            r"\w+@\w+\.\w+",
            r"https?://[^\s]+",
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
            r"^MZ.*PE\x00\x00",
            r"(cmd|powershell)\.exe",
        ]

        modifiers = []
        if random.random() > 0.6:
            modifiers.append("i")
        if random.random() > 0.8:
            modifiers.append("s")

        modifier_str = "".join(modifiers)
        if modifier_str:
            modifier_str = f"/{modifier_str}"

        return f"/{random.choice(patterns)}/{modifier_str}"

    def generate_strings_section(self, count: int | None = None) -> str:
        """Generate a strings section with multiple string definitions.

        Args:
            count: Number of strings to generate (random if None)

        Returns:
            YARA strings section
        """
        if count is None:
            count = random.randint(3, 15)

        lines = ["    strings:"]

        for i in range(count):
            var_name = f"$s{i + 1}"

            # Choose string type
            choice = random.random()
            if choice < 0.4:
                string_def = self.generate_plain_string()
            elif choice < 0.7:
                string_def = self.generate_hex_string()
            else:
                string_def = self.generate_regex_string()

            lines.append(f"        {var_name} = {string_def}")

        return "\n".join(lines)

    def generate_simple_condition(self, string_count: int) -> str:
        """Generate a simple condition expression.

        Args:
            string_count: Number of strings defined in the rule

        Returns:
            YARA condition string
        """
        conditions = [
            "any of them",
            "all of them",
            f"{random.randint(1, string_count)} of them",
            f"$s{random.randint(1, min(string_count, 5))}",
            f"$s{random.randint(1, min(string_count, 5))} at 0",
        ]
        return random.choice(conditions)

    def generate_complex_condition(self, string_count: int) -> str:
        """Generate a complex condition with multiple expressions.

        Args:
            string_count: Number of strings defined in the rule

        Returns:
            YARA condition string
        """
        conditions = []

        # Add filesize check
        if random.random() > 0.5:
            size = random.choice([100, 1000, 10000, 100000])
            operator = random.choice(["<", ">", "=="])
            conditions.append(f"filesize {operator} {size}KB")

        # Add string matching
        if random.random() > 0.3:
            count = random.randint(1, min(string_count, 5))
            conditions.append(f"{count} of them")

        # Add at position check
        if random.random() > 0.6:
            var = random.randint(1, min(string_count, 5))
            conditions.append(f"$s{var} at 0")

        # Add in range check
        if random.random() > 0.7:
            var = random.randint(1, min(string_count, 5))
            start = random.randint(0, 1000)
            end = start + random.randint(100, 5000)
            conditions.append(f"$s{var} in ({start}..{end})")

        if not conditions:
            conditions.append("any of them")

        operator = " and " if random.random() > 0.5 else " or "
        return operator.join(conditions)

    def generate_rule(
        self,
        complexity: str = "medium",
        include_meta: bool = True,
    ) -> str:
        """Generate a complete YARA rule.

        Args:
            complexity: Rule complexity level (simple, medium, complex)
            include_meta: Whether to include meta section

        Returns:
            Complete YARA rule string
        """
        rule_name = self.generate_identifier()

        # Determine string count based on complexity
        if complexity == "simple":
            string_count = random.randint(1, 5)
        elif complexity == "medium":
            string_count = random.randint(3, 10)
        else:  # complex
            string_count = random.randint(10, 20)

        lines = [f"rule {rule_name} {{"]

        # Add meta section
        if include_meta:
            lines.append(self.generate_meta_section())

        # Add strings section
        lines.append(self.generate_strings_section(string_count))

        # Add condition section
        lines.append("    condition:")
        if complexity == "simple":
            condition = self.generate_simple_condition(string_count)
        else:
            condition = self.generate_complex_condition(string_count)

        lines.append(f"        {condition}")
        lines.append("}")

        return "\n".join(lines)

    def generate_file(
        self,
        target_size_mb: float,
        output_path: Path,
        complexity_mix: dict | None = None,
    ) -> dict:
        """Generate a YARA file of specified size.

        Args:
            target_size_mb: Target file size in megabytes
            output_path: Path where the file will be written
            complexity_mix: Dictionary with complexity distribution
                           e.g., {"simple": 0.3, "medium": 0.5, "complex": 0.2}

        Returns:
            Dictionary with generation statistics
        """
        if complexity_mix is None:
            complexity_mix = {"simple": 0.2, "medium": 0.6, "complex": 0.2}

        target_bytes = int(target_size_mb * 1024 * 1024)

        rules = []
        current_size = 0
        rule_count = 0

        # Add common imports at the beginning
        imports = [
            'import "pe"',
            'import "elf"',
            'import "math"',
            'import "hash"',
        ]

        file_content = "\n".join(imports) + "\n\n"
        current_size = len(file_content.encode("utf-8"))

        # Generate rules until target size is reached
        while current_size < target_bytes:
            # Select complexity based on mix
            rand_val = random.random()
            cumulative = 0
            complexity = "medium"

            for comp, prob in complexity_mix.items():
                cumulative += prob
                if rand_val < cumulative:
                    complexity = comp
                    break

            rule = self.generate_rule(complexity=complexity)
            rule_size = len(rule.encode("utf-8")) + 2  # +2 for newlines

            rules.append(rule)
            current_size += rule_size
            rule_count += 1

            # Add progress feedback every 100 rules
            if rule_count % 100 == 0:
                progress_mb = current_size / (1024 * 1024)
                print(f"Generated {rule_count} rules ({progress_mb:.2f} MB)")

        # Write to file
        file_content += "\n\n".join(rules)
        output_path.write_text(file_content, encoding="utf-8")

        actual_size_mb = current_size / (1024 * 1024)

        return {
            "rule_count": rule_count,
            "target_size_mb": target_size_mb,
            "actual_size_mb": actual_size_mb,
            "file_path": str(output_path),
            "complexity_mix": complexity_mix,
        }


def generate_test_files(
    output_dir: Path,
    sizes_mb: list[float] | None = None,
) -> list[dict]:
    """Generate a suite of test files for benchmarking.

    Args:
        output_dir: Directory where test files will be created
        sizes_mb: List of file sizes in megabytes to generate

    Returns:
        List of dictionaries with generation statistics
    """
    if sizes_mb is None:
        sizes_mb = [5, 10, 18, 20, 50]

    output_dir.mkdir(parents=True, exist_ok=True)
    generator = YaraTestFileGenerator()

    results = []

    for size_mb in sizes_mb:
        print(f"\nGenerating {size_mb}MB test file...")
        output_path = output_dir / f"test_rules_{int(size_mb)}mb.yar"

        stats = generator.generate_file(
            target_size_mb=size_mb,
            output_path=output_path,
        )

        results.append(stats)
        print(f"Created: {output_path}")
        print(f"  Rules: {stats['rule_count']}")
        print(f"  Actual size: {stats['actual_size_mb']:.2f} MB")

    return results


if __name__ == "__main__":
    # Example usage
    benchmark_dir = Path(__file__).parent / "test_data"

    print("YARA Test File Generator")
    print("=" * 50)

    results = generate_test_files(benchmark_dir)

    print("\nGeneration complete!")
    print(f"Total files: {len(results)}")
    print(f"Total size: {sum(r['actual_size_mb'] for r in results):.2f} MB")
