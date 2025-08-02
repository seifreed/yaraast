"""Example: Basic YARA file parsing."""

from yaraast import CodeGenerator, Parser

# Example YARA rule
yara_rule = '''
import "pe"
import "math"

rule APT_Malware {
    meta:
        author = "Security Research Team"
        description = "Detects APT malware variant"
        date = "2024-01-01"
        version = 1

    strings:
        $mz = { 4D 5A }  // MZ header
        $string1 = "cmd.exe" nocase
        $string2 = "powershell.exe" wide
        $hex_pattern = { 48 8B ?? ?? 48 89 ?? ?? }
        $regex = /[a-z]{5}\.exe/i

    condition:
        $mz at 0 and
        2 of ($string*) and
        $hex_pattern and
        filesize < 1MB
}

rule Ransomware_Detector {
    meta:
        severity = "high"
        category = "ransomware"

    strings:
        $ransom_note = "Your files have been encrypted"
        $bitcoin = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $extensions = /\.(locked|encrypted|enc)$/

    condition:
        any of them
}
'''

# Parse the YARA rules
parser = Parser(yara_rule)
ast = parser.parse()

print(f"Parsed {len(ast.rules)} rules:")
for rule in ast.rules:
    print(f"  - {rule.name}")
    if rule.meta:
        print(f"    Meta fields: {', '.join(rule.meta.keys())}")
    print(f"    Strings: {len(rule.strings)}")
    print()

# Regenerate the code
generator = CodeGenerator()
regenerated = generator.generate(ast)

print("Regenerated YARA code:")
print("=" * 50)
print(regenerated)
