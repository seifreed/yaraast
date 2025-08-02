import "math"

include "network.yar"

rule check_entropy {
    meta:
        description = "Check for high entropy sections"

    condition:
        math.entropy(0, filesize) > 7.0 or
        for any i in (0..pe.number_of_sections - 1):
            (math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.5)
}

rule packed_executable {
    meta:
        description = "Detect packed executables"

    strings:
        $upx = { 55 50 58 21 }  // UPX!
        $aspack = { 60 E8 00 00 00 00 5D 81 ED }

    condition:
        any of them or
        check_entropy
}
