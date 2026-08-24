rule defined_expression
{
    strings:
        $optional = "optional"
    condition:
        defined $optional or true
}
