"""Simple roundtrip test implementation."""

from typing import Any

from yaraast.codegen import CodeGenerator
from yaraast.parser import Parser


def simple_roundtrip_test(yara_source: str) -> dict[str, Any]:
    """Perform a simple roundtrip test."""

    try:
        # Parse original
        parser = Parser()
        original_ast = parser.parse(yara_source)

        # Generate code from AST
        generator = CodeGenerator()
        reconstructed = generator.generate(original_ast)

        # Compare
        original_normalized = yara_source.strip()
        reconstructed_normalized = reconstructed.strip()

        # Basic comparison
        differences = []
        success = True

        # Compare content (ignoring whitespace differences)
        original_lines = [line.strip() for line in original_normalized.split("\n") if line.strip()]
        reconstructed_lines = [
            line.strip() for line in reconstructed_normalized.split("\n") if line.strip()
        ]

        if original_lines != reconstructed_lines:
            success = False
            if len(original_lines) != len(reconstructed_lines):
                differences.append(
                    f"Line count differs: {len(original_lines)} vs {len(reconstructed_lines)}"
                )

            for i, (orig, recon) in enumerate(
                zip(original_lines, reconstructed_lines, strict=False)
            ):
                if orig != recon:
                    differences.append(f"Line {i + 1} differs: '{orig}' vs '{recon}'")
                    if len(differences) > 5:  # Limit differences shown
                        differences.append("... more differences")
                        break

        return {
            "original_source": original_normalized,
            "reconstructed_source": reconstructed_normalized,
            "round_trip_successful": success,
            "differences": differences,
            "metadata": {
                "original_rule_count": len(original_ast.rules) if original_ast else 0,
                "reconstructed_rule_count": len(original_ast.rules) if original_ast else 0,
            },
        }

    except Exception as e:
        return {
            "original_source": yara_source,
            "reconstructed_source": "",
            "round_trip_successful": False,
            "differences": [f"Error during roundtrip: {e!s}"],
            "metadata": {},
        }
