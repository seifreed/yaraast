import "pe"

rule with_and_len {
    condition:
        with section_count = pe.sections.len(), minimum = 0 : (
            section_count >= minimum
        )
}
