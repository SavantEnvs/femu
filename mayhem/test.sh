#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the known-answer tests that mayhem/build.sh built (it never compiles): the vendored libraries' KATs and FEMU's own TAP unit tests.
# Each program asserts concrete values (decoded bytes, digests, parsed fields, match offsets) and prints
# `PASS <name>` / `FAIL <name>` plus a final `SUMMARY pass=N fail=M`. A program that prints no SUMMARY
# (crashed, or neutered into a no-op) counts as one failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

EDK2="$SRC/roms/edk2"
T="$SRC/mayhem/build/tests"
passed=0; failed=0

run() {   # <program> <data dir>   (expected-minimum PASS lines guards against silent truncation)
  local prog="$1" dir="$2" min="$3" out p f
  if [ ! -x "$T/$prog" ]; then echo "FAIL missing test binary $T/$prog (build.sh must produce it)"; failed=$((failed+1)); return; fi
  out="$("$T/$prog" "$dir" 2>&1)"; echo "$out"
  if ! grep -q '^SUMMARY ' <<<"$out"; then echo "FAIL $prog produced no SUMMARY"; failed=$((failed+1)); return; fi
  p=$(grep -c '^PASS ' <<<"$out"); f=$(grep -c '^FAIL ' <<<"$out")
  [ "$p" -ge "$min" ] || { echo "FAIL $prog ran only $p tests (expected >= $min)"; f=$((f+1)); }
  passed=$((passed+p)); failed=$((failed+f))
}

run_tap() {   # <program> <min>   FEMU's own unit tests: TAP lines "ok N - ..." / "not ok N - ...", exit 1 on any failure
  local prog="$1" min="$2" out rc p f
  if [ ! -x "$T/$prog" ]; then echo "FAIL missing test binary $T/$prog (build.sh must produce it)"; failed=$((failed+1)); return; fi
  out="$("$T/$prog" 2>&1)"; rc=$?; echo "$out" | tail -n 5
  p=$(grep -c '^ok ' <<<"$out"); f=$(grep -c '^not ok ' <<<"$out")
  [ "$rc" -eq 0 ] || { echo "FAIL $prog exited $rc"; f=$((f+1)); }
  [ "$p" -ge "$min" ] || { echo "FAIL $prog ran only $p checks (expected >= $min)"; f=$((f+1)); }
  echo "$prog: $p ok, $f failed"
  passed=$((passed+p)); failed=$((failed+f))
}

run test_brotli  "$EDK2/BaseTools/Source/C/BrotliCompress/brotli/tests/testdata" 13
run test_mbedtls "$EDK2/CryptoPkg/Library/MbedTlsLib/mbedtls/tests/data_files" 8
run test_jansson "" 8
run test_onig    "" 7

run_tap test_femu_nand_media 70
run_tap test_femu_onfi_timing 195
run_tap test_femu_kv_lsm 99
run_tap test_femu_kv_pack 42

emit_ctrf "known-answer" "$passed" "$failed" 0
