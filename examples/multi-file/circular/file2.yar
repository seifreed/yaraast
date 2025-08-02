include "file1.yar"  // This creates a circular dependency!

rule rule_from_file2 {
    condition:
        false
}
