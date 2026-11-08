import "elf"
import "pe"

rule upstream_module_members {
    condition:
        elf.EM_PARISC == 15 and
        elf.EM_SPARC32PLUS == 18 and
        elf.EM_S390 == 22 and
        elf.EM_MCORE == 39 and
        elf.EM_RCE == 39 and
        elf.EM_SH == 42 and
        elf.EM_SPARCV9 == 43 and
        elf.EM_ARC_COMPACT == 93 and
        elf.EM_BPF == 247 and
        elf.EM_LOONGARCH == 258 and
        pe.offset_to_rva(0) == 0
}
