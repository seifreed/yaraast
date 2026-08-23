rule base64_alphabets {
    strings:
        $encoded = "foo" base64 base64wide("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    condition:
        $encoded
}
