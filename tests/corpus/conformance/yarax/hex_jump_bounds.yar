rule hex_jump_bounds {
    strings:
        $pattern = { 01 02 [0x00-0x100] 03 [0o10-0o20] 04 }
    condition:
        $pattern
}
