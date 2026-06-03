rule of_them
{
    strings:
        $a = "alpha"
        $b = "bravo"
        $c = "charlie"
    condition:
        2 of them
}

rule of_subset
{
    strings:
        $s1 = "one"
        $s2 = "two"
    condition:
        any of ($s1, $s2)
}

rule of_wildcard_set
{
    strings:
        $pre1 = "prefix_a"
        $pre2 = "prefix_b"
    condition:
        all of ($pre*)
}

rule for_any_in_range
{
    strings:
        $a = "needle"
    condition:
        for any i in (1..#a) : ( @a[i] > 0 )
}

rule for_all_of_set
{
    strings:
        $a = "x"
        $b = "y"
    condition:
        for all of ($a, $b) : ( # > 0 )
}

rule percent_of_them
{
    strings:
        $a = "p"
        $b = "q"
        $c = "r"
        $d = "s"
    condition:
        50% of them
}
