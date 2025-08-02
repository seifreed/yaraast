rule common_strings_found {
    meta:
        description = "Common malicious strings"

    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAllocEx"
        $api3 = "WriteProcessMemory"
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $cmd1 = "powershell -enc"
        $cmd2 = "certutil -decode"

    condition:
        2 of ($api*) or
        any of ($reg*) or
        any of ($cmd*)
}
