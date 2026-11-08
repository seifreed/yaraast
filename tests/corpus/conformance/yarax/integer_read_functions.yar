rule integer_read_functions {
    condition:
        uint64(0) == 0x0807060504030201 and
        int64(8) == -1 and
        uint64be(16) == 0x0102030405060708 and
        int64be(24) == -1
}
