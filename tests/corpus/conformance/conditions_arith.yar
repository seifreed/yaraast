rule arithmetic_and_bitwise
{
    condition:
        (2 + 3) * 4 == 20 and (0xF0 | 0x0F) == 0xFF and (5 % 2) == 1
}

rule shifts_and_xor
{
    condition:
        (1 << 4) == 16 and (256 >> 2) == 64 and (0xAA ^ 0xFF) == 0x55
}

rule comparisons_and_logic
{
    condition:
        filesize > 0 and not (filesize == 0) and (filesize <= 0xFFFFFFFF)
}

rule boolean_grouping
{
    strings:
        $a = "x"
        $b = "y"
    condition:
        ($a and not $b) or ($b and not $a)
}

rule float_arithmetic
{
    condition:
        (3.5 + 1.5) == 5.0 and (2.0 * 2.5) == 5.0
}
