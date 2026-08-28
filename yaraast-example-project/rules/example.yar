rule example_hello {
    meta:
        id = "EXAMPLE-HELLO"
        status = "production"
    strings:
        $hello = "hello"
    condition:
        $hello
}
