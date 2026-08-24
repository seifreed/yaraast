rule string_modifiers
{
    strings:
        $ascii = "ascii" ascii
        $wide = "wide" wide nocase
        $base64 = "Zm9v" base64
        $xor = "xor" xor(1-3)
    condition:
        all of them
}
