#!/bin/bash -eu

python3 -m pip install .

for target in parser roundtrip; do
  pyinstaller --distpath "$OUT" --onefile \
    --name "yaraast_${target}_fuzzer.pkg" "fuzz/run_${target}_fuzz.py"
  cat > "$OUT/yaraast_${target}_fuzzer" <<EOF
#!/bin/sh
exec "\$(dirname "\$0")/yaraast_${target}_fuzzer.pkg" "\$@"
EOF
  chmod +x "$OUT/yaraast_${target}_fuzzer"
done
