rule regex_basic
{
    strings:
        $email = /[a-z0-9._]+@[a-z0-9.]+\.[a-z]{2,}/
    condition:
        $email
}

rule regex_flags
{
    strings:
        $i = /malware/i
        $s = /start.end/s
    condition:
        any of them
}

rule regex_classes
{
    strings:
        $hex = /0x[0-9A-Fa-f]+/
        $word = /\b[A-Z][a-z]+\b/
    condition:
        any of them
}

rule regex_anchors_quantifiers
{
    strings:
        $q = /ab{2,4}c?d*e+/
        $alt = /(foo|bar|baz)+/
    condition:
        any of them
}

rule regex_charclass_slash
{
    strings:
        $slash = /[\/\\]path[\/\\]to/
    condition:
        $slash
}
