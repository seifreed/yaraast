rule text_basic
{
    strings:
        $a = "hello world"
    condition:
        $a
}

rule text_modifiers
{
    strings:
        $nocase = "Mozilla" nocase
        $wide = "kernel32" wide ascii
        $full = "admin" fullword
    condition:
        any of them
}

rule text_xor
{
    strings:
        $x = "secret" xor
        $xr = "token" xor(0x01-0xff)
    condition:
        any of them
}

rule text_base64
{
    strings:
        $b = "payload" base64
        $bw = "config" base64wide
    condition:
        any of them
}

rule text_private
{
    strings:
        $p = "internal" private
    condition:
        $p
}

rule text_escapes
{
    strings:
        $tab = "a\tb"
        $quote = "say \"hi\""
        $nl = "line1\nline2"
    condition:
        any of them
}
