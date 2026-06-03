import "pe"
import "elf"
import "math"
import "hash"
import "time"

rule pe_basics
{
    condition:
        pe.number_of_sections >= 0 and pe.is_pe == pe.is_pe
}

rule elf_basics
{
    condition:
        elf.number_of_sections >= 0
}

rule math_entropy
{
    condition:
        math.entropy(0, filesize) >= 0.0 and math.mean(0, filesize) >= 0.0
}

rule hash_of_region
{
    condition:
        hash.md5(0, filesize) == hash.md5(0, filesize)
}

rule time_now
{
    condition:
        time.now() > 0
}
