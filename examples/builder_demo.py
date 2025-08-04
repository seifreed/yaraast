"""Example demonstrating the fluent builder pattern."""

from yaraast import (
    CodeGenerator,
    ConditionBuilder,
    ExpressionBuilder,
    HexStringBuilder,
    RuleBuilder,
    YaraFileBuilder,
)
from yaraast.types import TypeValidator


def main() -> None:
    # Example 1: Simple rule with builder
    print("=== Example 1: Simple Rule ===")

    simple_rule = (
        RuleBuilder()
        .with_name("simple_malware")
        .with_tag("malware")
        .with_tag("trojan")
        .with_author("Security Researcher")
        .with_description("Detects simple malware patterns")
        .with_plain_string("$mz", "MZ", ascii=True)
        .with_plain_string("$pe", "PE", nocase=True)
        .with_hex_string_raw("$hex1", "48 65 6C 6C 6F")
        .with_regex("$url", r"https?://[a-z0-9\.\-]+", case_insensitive=True)
        .with_condition("all of them")
        .build()
    )

    generator = CodeGenerator()
    print(generator.generate(simple_rule))
    print()

    # Example 2: Advanced hex strings with nibbles and jumps
    print("=== Example 2: Advanced Hex Strings ===")

    hex_builder = (
        HexStringBuilder()
        .add(0x4D)
        .add(0x5A)  # MZ header
        .wildcard(2)  # ?? ??
        .nibble("F?")  # F? - high nibble
        .nibble("?0")  # ?0 - low nibble
        .jump_varying(4, 8)  # [4-8]
        .alternative(
            [0x50, 0x45],  # PE
            [0x45, 0x4C, 0x46],  # ELF
        )
        .jump_any()  # [-]
        .add_bytes(0xFF, 0xFE)
    )

    advanced_rule = (
        RuleBuilder()
        .with_name("advanced_hex_patterns")
        .with_hex_string("$pattern", hex_builder)
        .with_condition(ConditionBuilder.match("$pattern"))
        .build()
    )

    print(generator.generate(advanced_rule))
    print()

    # Example 3: Module access and complex conditions
    print("=== Example 3: Module Access ===")

    module_rule = (
        RuleBuilder()
        .with_name("pe_module_example")
        .private()
        .with_meta("platform", "windows")
        .with_plain_string("$suspicious", "cmd.exe")
        .with_condition_lambda(
            lambda c: c.string("$suspicious")
            .and_(c.identifier("pe.machine").eq(c.integer(0x14C)))
            .and_(c.identifier("pe.number_of_sections").gt(c.integer(3)))
            .and_(c.member_access(c.identifier("pe"), "is_dll").eq(c.false()))
        )
        .build()
    )

    # Create a file with imports
    yara_file = (
        YaraFileBuilder().with_import("pe").with_import("math").with_rule(module_rule).build()
    )

    print(generator.generate(yara_file))
    print()

    # Example 4: Complex conditions with loops
    print("=== Example 4: Complex Conditions ===")

    complex_rule = (
        RuleBuilder()
        .with_name("complex_conditions")
        .with_plain_string("$a", "evil")
        .with_plain_string("$b", "malicious")
        .with_plain_string("$c", "dangerous")
        .with_hex_string_raw("$hex", "48 8B ?? ?? 48 89 ?? ??")
        .with_condition_lambda(
            lambda c:
            # 2 of ($a, $b, $c)
            c.n_of(2, "$a", "$b", "$c")
            .and_(
                # $hex at entrypoint
                c.string("$hex").at(c.entrypoint())
            )
            .and_(
                # for any i in (0..pe.number_of_sections):
                c.for_any(
                    "i",
                    c.range(c.integer(0), c.identifier("pe.number_of_sections")),
                    c.member_access(
                        c.array_access(c.identifier("pe.sections"), c.identifier("i")),
                        "characteristics",
                    )
                    .bitwise_and(c.integer(0x20000000))
                    .ne(c.integer(0)),
                )
            )
        )
        .build()
    )

    complex_file = YaraFileBuilder().with_import("pe").with_rule(complex_rule).build()

    print(generator.generate(complex_file))
    print()

    # Example 5: Type validation
    print("=== Example 5: Type Validation ===")

    # This will have type errors
    invalid_rule = (
        RuleBuilder()
        .with_name("type_errors")
        .with_plain_string("$str", "test")
        .with_condition_lambda(
            lambda c:
            # Type error: string comparison with integer
            c.string("$str").gt(c.integer(5))
        )
        .build()
    )

    invalid_file = YaraFileBuilder().with_rule(invalid_rule).build()

    is_valid, errors = TypeValidator.validate(invalid_file)
    if not is_valid:
        print("Type errors found:")
        for error in errors:
            print(f"  - {error}")
    print()

    # Example 6: Nested hex alternatives
    print("=== Example 6: Nested Hex Alternatives ===")

    nested_hex = (
        HexStringBuilder()
        .add(0x48)
        .alternative(
            [0x8B, 0x05],  # mov rax, [rip+...]
            [0x8B, 0x0D],  # mov rcx, [rip+...]
            [0x8B, 0x15],  # mov rdx, [rip+...]
        )
        .wildcard(4)  # offset
        .alternative(
            [0x48, 0x89],  # mov [dest], rax
            [0xFF, 0x15],  # call [rip+...]
        )
    )

    nested_rule = (
        RuleBuilder()
        .with_name("nested_alternatives")
        .with_hex_string("$code_pattern", nested_hex)
        .with_condition("$code_pattern")
        .build()
    )

    print(generator.generate(nested_rule))


if __name__ == "__main__":
    main()
