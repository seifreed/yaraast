# Signature Sweep (2026-06-29, advance-02)

Scope: 11 YARA files under `/Users/seifreed/tools/malware/signatures/YARA`.

- `clamav/clamav.yar`
- `hunting/HUNTING_BSS_logs.yar`
- `hunting/HUNTING_office.yar`
- `hunting/HUNTING_powershell.yar`
- `hunting/HUNTING_ransomware.yar`
- `hunting/HUNTING_special.yar`
- `hunting/TURLA_kazuar.yar`
- `iddqd.yar`
- `kaspersky/apt_kl.yara`
- `kaspersky/ics_kl.yara`
- `yara-rules-full.yar`

## Commands run

- `python -m yaraast bench --operations all --iterations 1 --file-timeout 120 --output /tmp/yara_perf_bench/advance_20260629_02/bench_parse.json $(find /Users/seifreed/tools/malware/signatures/YARA -type f \( -name '*.yar' -o -name '*.yara' \))`
- `python -m yaraast performance stream --recursive --pattern '*.y*' --file-timeout 120 /Users/seifreed/tools/malware/signatures/YARA > /tmp/yara_perf_bench/advance_20260629_02/stream_default.json`
- `python -m yaraast performance optimize 11 --memory-mb 1024 --target-time 300 > /tmp/yara_perf_bench/advance_20260629_02/optimize_300_02.txt`
- `python -m yaraast performance optimize 11 --memory-mb 1024 --target-time 180 > /tmp/yara_perf_bench/advance_20260629_02/optimize_180_02.txt`
- `python -m yaraast performance parse /Users/seifreed/tools/malware/signatures/YARA/clamav/clamav.yar --file-timeout 180 > /tmp/yara_perf_bench/advance_20260629_02/clamav_parse_180.txt`
- `python -m yaraast performance codegen /Users/seifreed/tools/malware/signatures/YARA/clamav/clamav.yar --file-timeout 180 > /tmp/yara_perf_bench/advance_20260629_02/clamav_codegen_180.txt`
- `python -m yaraast performance batch /Users/seifreed/tools/malware/signatures/YARA/clamav/clamav.yar --operation parse --split-rules --file-timeout 30` (artifacts in `/tmp/yara_perf_bench/advance_20260629_02/clamav_parse_split`)
- `python -m yaraast performance stream --file-timeout 120 /Users/seifreed/tools/malware/signatures/YARA/clamav/clamav.yar > /tmp/yara_perf_bench/advance_20260629_02/clamav_stream_split_120.txt`
- `python -m yaraast perfcheck /Users/seifreed/tools/malware/signatures/YARA/clamav/clamav.yar --timeout 120 > /tmp/yara_perf_bench/advance_20260629_02/perfcheck2/timeout.log`

Batch operations (`complexity`, `dependency_graph`, `html_tree`, `serialize`, `validate`, and `parse`) were also run per-file. Artifacts are in `/tmp/yara_perf_bench/advance_20260629_02/`.

## Aggregate results

| operation | files | success | fail | avg time | notes |
| --- | --- | --- | --- | --- | --- |
| parse | 11 | 9 | 2 | 4.092 s | bench mode |
| codegen | 11 | 7 | 4 | 8.351 s | bench mode |
| roundtrip | 11 | 7 | 4 | 9.045 s | bench mode |
| stream parse | 11 | 9 | 2 | n/a | streaming parser mode |
| complexity | 11 | 7 | 4 | n/a | batch per-file |
| dependency_graph | 11 | 9 | 2 | n/a | batch per-file |
| html_tree | 11 | 9 | 2 | n/a | batch per-file |
| serialize | 11 | 7 | 4 | n/a | batch per-file |
| validate | 11 | 9 | 2 | n/a | batch per-file |

`parse/codegen/roundtrip` averages from `bench_parse.json`, `bench_codegen.json`, and `bench_roundtrip.json`:
parse avg=4.092043s, rules/sec=376.64
codegen avg=8.351139s, rules/sec=42.95
roundtrip avg=9.044769s, rules/sec=39.66

`performance stream` for the same directory produced `success=9`, `failed=2` with errors:
- `iddqd.yar` (`Lexer error`)
- `clamav/clamav.yar` (parse timeout 120s)

## Per-file status matrix

Legend: `ok` means operation completed; `fail: <reason>` is from benchmark output.

| file | parse | codegen | roundtrip | complexity | dependency_graph | html_tree | serialize | validate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `clamav/clamav.yar` | fail: parse timeout 120s | fail: codegen timed out after 120s | fail: roundtrip timed out after 120s | fail: parse timeout 120s | fail: parse timeout 120s | fail: no batch result | fail: parse timeout 120s | fail: parse timeout 120s |
| `hunting/HUNTING_BSS_logs.yar` | ok | ok | ok | ok | ok | ok | ok | ok |
| `hunting/HUNTING_office.yar` | ok | ok | ok | ok | ok | ok | ok | ok |
| `hunting/HUNTING_powershell.yar` | ok | ok | ok | ok | ok | ok | ok | ok |
| `hunting/HUNTING_ransomware.yar` | ok | ok | ok | ok | ok | ok | ok | ok |
| `hunting/HUNTING_special.yar` | ok | fail: module imports required for libyara output: pe | fail: module imports required for libyara output: pe | ok | ok | ok | ok | ok |
| `hunting/TURLA_kazuar.yar` | ok | ok | ok | ok | ok | ok | ok | ok |
| `iddqd.yar` | fail: invalid escape sequence `\\%` | fail: parse failure | fail: parse failure | fail: parse failure | fail: parse failure | fail: parse failure | fail: parse failure | fail: parse failure |
| `kaspersky/apt_kl.yara` | ok | ok | ok | fail: base64 value must be a string | ok | ok | fail: Invalid string reference '$' | ok |
| `kaspersky/ics_kl.yara` | ok | ok | ok | ok | ok | ok | ok | ok |
| `yara-rules-full.yar` | ok | fail: codegen timeout 120s | fail: roundtrip timeout 120s | fail: base64 value must be a string | ok | ok | fail: Invalid string reference '$' | ok |

## Root causes

1. Grammar/data issues in source files:
   - `iddqd.yar`: invalid escape sequence (`\\%`) in a string literal.
2. Timeout pressure on a large file:
   - `clamav/clamav.yar`: parse/codegen/roundtrip still exceed 120s and 180s.
3. Module dependency:
   - `hunting/HUNTING_special.yar`: codegen/roundtrip require the `pe` module for libyara output.
4. Base64/string-reference analysis failures:
   - `kaspersky/apt_kl.yara` and `yara-rules-full.yar`: base64/string-reference issues in complexity/serialize paths.

## Improvement attempts

- Tried `--file-timeout 180` on `clamav/clamav.yar` for parse/codegen: still timeout.
- Tried split-rule parse on `clamav/clamav.yar` with `--file-timeout 30`: still timed out.
- `performance optimize` recommends `batch-size 10`, `memory-limit 100`, no pooling/streaming for both 180s and 300s.
- `perfcheck` with a 120s timeout returned `PERFCHECK_TIMEOUT` for `clamav.yar`.

## Recommended actions

- Fix `iddqd.yar` (`\%` escape) and clean the base64/string-reference rule issues before re-running heavy analyses.
- Exclude `clamav/clamav.yar` from full operation sweeps unless dedicated large-file handling is added.
- Install/configure libyara modules (`pe`) to run full codegen/roundtrip on `HUNTING_special.yar`.

## Reproducibility template

```bash
YARA_ROOT="/Users/seifreed/tools/malware/signatures/YARA"
OUT="/tmp/yara_perf_bench/signature-sweep-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

python -m yaraast bench --operations all --iterations 1 --file-timeout 120 \
  --output "$OUT/bench_all_ops.json" $(find "$YARA_ROOT" -type f \( -name '*.yar' -o -name '*.yara' \))

python -m yaraast performance stream --recursive --pattern '*.y*' --file-timeout 120 \
  "$YARA_ROOT" > "$OUT/stream_out.json"

python -m yaraast performance optimize 11 --memory-mb 1024 --target-time 300 \
  > "$OUT/optimize_300.txt"
python -m yaraast performance optimize 11 --memory-mb 1024 --target-time 180 \
  > "$OUT/optimize_180.txt"
```

Run artifact directory: `/tmp/yara_perf_bench/advance_20260629_02`.
