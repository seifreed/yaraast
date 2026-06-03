rule count_threshold
{
    strings:
        $a = "rep"
    condition:
        #a >= 3
}

rule offset_relations
{
    strings:
        $a = "first"
        $b = "second"
    condition:
        @a < @b and @a[1] >= 0
}

rule length_of_match
{
    strings:
        $re = /a+b/
    condition:
        !re[1] >= 2
}

rule string_at_and_in
{
    strings:
        $mz = "MZ"
        $tag = "TAG"
    condition:
        $mz at 0 and $tag in (0..256)
}

rule integer_readers
{
    condition:
        uint16(0) == 0x5A4D or uint8(0) == 0x4D or int32(0) != 0
}
