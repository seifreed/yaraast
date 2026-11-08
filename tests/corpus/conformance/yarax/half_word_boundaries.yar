rule half_word_boundaries {
    strings:
        $word = /\b{start-half}foo\b{end-half}/
    condition:
        $word
}
