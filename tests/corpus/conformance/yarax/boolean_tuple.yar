rule boolean_tuple {
    strings:
        $needle = "needle"
    condition:
        1 of ($needle and true, false)
}
