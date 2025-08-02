rule suspicious_network_strings {
    meta:
        description = "Network-related suspicious strings"

    strings:
        $ip1 = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/
        $url1 = /https?:\/\/[a-z0-9\.\-]+\.(?:tk|ml|ga|cf)/i
        $dns1 = "8.8.8.8"
        $dns2 = "8.8.4.4"
        $port1 = ":4444"
        $port2 = ":8080"
        $port3 = ":1337"

    condition:
        any of ($ip*) or
        any of ($url*) or
        all of ($dns*) or
        2 of ($port*)
}
