"""Example: Transforming YARA AST."""

from yaraast import ASTTransformer, CodeGenerator, Parser
from yaraast.ast import *


# Example transformer that adds a prefix to all rule names
class RulePrefixTransformer(ASTTransformer):
    def __init__(self, prefix: str):
        self.prefix = prefix

    def visit_rule(self, node: Rule) -> Rule:
        # Call parent to transform children
        transformed = super().visit_rule(node)

        # Modify the rule name
        transformed.name = f"{self.prefix}_{transformed.name}"

        # Add a meta field indicating transformation
        transformed.meta["transformed"] = "true"
        transformed.meta["prefix"] = self.prefix

        return transformed

# Example transformer that converts all plain strings to nocase
class NoCaseTransformer(ASTTransformer):
    def visit_plain_string(self, node: PlainString) -> PlainString:
        transformed = super().visit_plain_string(node)

        # Check if nocase modifier already exists
        has_nocase = any(mod.name == "nocase" for mod in transformed.modifiers)

        if not has_nocase:
            # Add nocase modifier
            nocase_mod = StringModifier(name="nocase")
            transformed.modifiers.append(nocase_mod)

        return transformed

# Original YARA rule
original_yara = '''
rule detect_malware {
    meta:
        author = "Analyst"
    strings:
        $a = "malicious"
        $b = "dangerous"
        $c = "evil" nocase
    condition:
        any of them
}

rule detect_backdoor {
    strings:
        $cmd = "cmd.exe"
        $shell = "shell32.dll"
    condition:
        all of them
}
'''

# Parse the original rules
parser = Parser(original_yara)
ast = parser.parse()

print("Original rules:")
print("=" * 50)
generator = CodeGenerator()
print(generator.generate(ast))

# Apply prefix transformer
prefix_transformer = RulePrefixTransformer("CORP")
prefixed_ast = prefix_transformer.visit(ast)

print("\nAfter adding prefix:")
print("=" * 50)
print(generator.generate(prefixed_ast))

# Apply nocase transformer
nocase_transformer = NoCaseTransformer()
nocase_ast = nocase_transformer.visit(prefixed_ast)

print("\nAfter adding nocase to all strings:")
print("=" * 50)
print(generator.generate(nocase_ast))
