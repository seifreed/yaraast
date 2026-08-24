rule regex_modifiers
{
    strings:
        $pattern = /malware[0-9]+/ nocase ascii
    condition:
        $pattern
}
