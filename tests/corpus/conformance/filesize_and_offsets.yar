rule filesize_and_offsets
{
    strings:
        $mz = "MZ"
    condition:
        filesize >= 2 and $mz at 0
}
