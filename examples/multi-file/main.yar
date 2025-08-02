import "pe"
import "math"

include "common/strings.yar"
include "common/utils.yar"

rule Main_Malware_Detection {
    meta:
        author = "Security Team"
        description = "Main detection rule using includes"
        version = "1.0"

    strings:
        $mz = { 4D 5A }
        $suspicious = "cmd.exe" nocase

    condition:
        $mz at 0 and
        pe.machine == 0x14c and
        common_strings_found and
        check_entropy and
        any of ($suspicious*)
}
