#!/usr/bin/env python3
"""VirusTotal LiveHunt Module Support Demo.

This example demonstrates the comprehensive VT LiveHunt module support
in yaraast, including:

1. Legacy global identifiers (new_file, positives, submissions)
2. VT module metadata fields (vt.metadata.*)
3. VT behavioral analysis fields (vt.behaviour.*)
4. Type checking and validation
"""

from yaraast.parser.parser import Parser
from yaraast.types.type_system import TypeChecker


def demo_legacy_identifiers():
    """Demo: Legacy VT identifiers work without import."""
    print("=" * 70)
    print("1. Legacy VT Identifiers (No Import Required)")
    print("=" * 70)

    code = """
rule vt_hunt_new_malware {
    meta:
        description = "Hunt for new files with high detection rate"
        author = "Threat Intel Team"

    strings:
        $malicious = "malware_signature"
        $c2 = "http://malicious.com"

    condition:
        new_file and                    // File is new to VT
        positives > 5 and               // More than 5 AV detections
        submissions < 10 and            // Few submissions (targeted)
        ($malicious or $c2)
}
"""

    ast = Parser(code).parse()
    print(f"✓ Parsed rule: {ast.rules[0].name}")

    checker = TypeChecker()
    errors = checker.check(ast)
    if errors:
        print(f"  Type errors: {errors}")
    else:
        print("✓ Type checking passed")

    print("\nExplanation:")
    print("  - new_file: boolean, indicates file is new to VirusTotal")
    print("  - positives: integer, number of AV engines detecting as malicious")
    print("  - submissions: integer, number of times file was submitted")
    print()


def demo_vt_metadata():
    """Demo: VT module with metadata fields."""
    print("=" * 70)
    print("2. VT Metadata Fields")
    print("=" * 70)

    code = """
import "vt"

rule vt_targeted_malware {
    meta:
        description = "Detect targeted malware based on VT metadata"

    condition:
        vt.metadata.analysis_stats.malicious > 3 and
        vt.metadata.file_size < 5000000 and
        vt.metadata.first_submission_date > 1704067200 and  // After 2024
        vt.metadata.file_type_tags contains "executable"
}
"""

    ast = Parser(code).parse()
    print(f"✓ Parsed rule: {ast.rules[0].name}")
    print(f"  Import: {ast.imports[0].module}")

    checker = TypeChecker()
    errors = checker.check(ast)
    if errors:
        print(f"  Type errors: {errors}")
    else:
        print("✓ Type checking passed")

    print("\nAvailable VT Metadata Fields:")
    print("  - vt.metadata.md5/sha1/sha256: File hashes")
    print("  - vt.metadata.file_name/file_size/file_type: Basic file info")
    print("  - vt.metadata.analysis_stats: Detection statistics")
    print("  - vt.metadata.submitter.country/city: Submitter location")
    print("  - vt.metadata.tags/malware_families: Classification tags")
    print()


def demo_vt_behaviour():
    """Demo: VT behavioral analysis."""
    print("=" * 70)
    print("3. VT Behavioral Analysis")
    print("=" * 70)

    code = """
import "vt"

rule vt_ransomware_behavior {
    meta:
        description = "Detect ransomware-like behavior via VT sandbox"

    condition:
        // Check for file operations
        for any file in vt.behaviour.files_dropped : (
            file.path contains ".exe" or
            file.path contains ".dll"
        ) and

        // Check for network activity
        for any conn in vt.behaviour.http_conversations : (
            conn.url contains "onion" or
            conn.url contains "tor"
        ) and

        // Check for registry modifications
        for any reg in vt.behaviour.registry_keys_set : (
            reg.key contains "CurrentVersion\\Run"
        )
}
"""

    ast = Parser(code).parse()
    print(f"✓ Parsed rule: {ast.rules[0].name}")

    checker = TypeChecker()
    errors = checker.check(ast)
    if errors:
        print(f"  Type errors: {errors}")
    else:
        print("✓ Type checking passed")

    print("\nAvailable VT Behavior Fields:")
    print("  - vt.behaviour.files_dropped/deleted/opened/written")
    print("  - vt.behaviour.dns_lookups")
    print("  - vt.behaviour.http_conversations")
    print("  - vt.behaviour.ip_traffic")
    print("  - vt.behaviour.processes_created/injected/killed")
    print("  - vt.behaviour.registry_keys_set")
    print("  - vt.behaviour.traits/verdicts: Behavioral classification")
    print()


def demo_combined_usage():
    """Demo: Combined legacy and module usage."""
    print("=" * 70)
    print("4. Combined Legacy and Module Usage")
    print("=" * 70)

    code = """
import "vt"
import "pe"

rule comprehensive_vt_hunt {
    meta:
        description = "Comprehensive VT LiveHunt rule"
        author = "Security Team"

    strings:
        $packer = { 55 8B EC 83 C4 ?? 53 56 57 }
        $suspicious = "cmd.exe /c" wide

    condition:
        // Legacy identifiers for initial filtering
        new_file and
        positives > 2 and

        // VT metadata checks
        vt.metadata.file_size < 2000000 and
        vt.metadata.analysis_stats.malicious > 1 and

        // PE-specific checks
        pe.is_pe and
        pe.number_of_sections < 5 and

        // String matches
        ($packer or $suspicious)
}
"""

    ast = Parser(code).parse()
    print(f"✓ Parsed rule: {ast.rules[0].name}")
    print(f"  Imports: {[imp.module for imp in ast.imports]}")

    checker = TypeChecker()
    errors = checker.check(ast)
    if errors:
        print(f"  Type errors: {errors}")
    else:
        print("✓ Type checking passed")

    print("\nRule successfully validated with VT, PE modules and legacy identifiers!")


def demo_module_info():
    """Demo: Show available VT module information."""
    print("=" * 70)
    print("5. VT Module Information")
    print("=" * 70)

    from yaraast.types.module_loader import ModuleLoader

    loader = ModuleLoader()
    vt_module = loader.get_module("vt")

    if vt_module:
        print(f"Module: {vt_module.name}")
        print(f"\nTop-level attributes ({len(vt_module.attributes)}):")
        for attr_name in sorted(vt_module.attributes.keys()):
            attr_type = vt_module.attributes[attr_name]
            print(f"  - vt.{attr_name}: {attr_type}")

        print(f"\nConstants ({len(vt_module.constants)}):")
        for const_name in sorted(vt_module.constants.keys()):
            const_type = vt_module.constants[const_name]
            print(f"  - {const_name}: {const_type}")
    else:
        print("VT module not loaded!")


if __name__ == "__main__":
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "VirusTotal LiveHunt Support Demo" + " " * 21 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    demo_legacy_identifiers()
    demo_vt_metadata()
    demo_vt_behaviour()
    demo_combined_usage()
    demo_module_info()

    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print("✓ Legacy VT identifiers supported (new_file, positives, submissions)")
    print("✓ Full VT module with metadata and behavioral fields")
    print("✓ Type checking validates VT-specific syntax")
    print("✓ Compatible with existing YARA modules (pe, elf, etc.)")
    print()
    print("For more information, see:")
    print("  https://docs.virustotal.com/docs/writing-yara-rules-for-livehunt")
    print()
