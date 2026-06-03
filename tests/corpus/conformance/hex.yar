rule hex_bytes
{
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule hex_wildcards
{
    strings:
        $w = { 4D 5A ?? ?? 50 45 }
    condition:
        $w
}

rule hex_nibbles
{
    strings:
        $hi = { 4? 5A }
        $lo = { 4D ?A }
    condition:
        all of them
}

rule hex_jumps
{
    strings:
        $j = { 4D 5A [2-6] 50 45 }
        $open = { 90 90 [4-] C3 }
    condition:
        any of them
}

rule hex_alternatives
{
    strings:
        $alt = { 4D ( 5A | 5B | 5C ) 90 }
    condition:
        $alt
}

rule hex_negated
{
    strings:
        $neg = { 4D ~5A 90 }
    condition:
        $neg
}
