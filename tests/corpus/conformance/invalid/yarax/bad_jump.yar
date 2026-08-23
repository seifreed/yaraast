rule bad_jump {
    strings:
        $a = { 4D [10-2] 5A }
    condition:
        $a
}
