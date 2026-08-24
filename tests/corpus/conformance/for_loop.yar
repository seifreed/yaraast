rule for_loop
{
    strings:
        $a = "a"
    condition:
        for any i in (1..2) : (i == 1) and $a
}
