#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harnesses and the known-answer test programs used by mayhem/test.sh.
#
# Two groups of fuzz targets:
#  * FEMU's own modules (hw/femu/kvssd/kv-lsm.c, kv-pack.c, hw/femu/nand/nand-media.c, onfi.c). They need nothing
#    from QEMU beyond osdep.h, which hw/femu/tests/qemu/osdep.h stubs (that is how hw/femu/tests/Makefile builds
#    them "without QEMU"); the harnesses live under mayhem/<target>/harness.c.
#  * The third-party libraries vendored under roms/edk2 (brotli, mbedTLS, jansson, oniguruma), whose upstream
#    libFuzzer harnesses are used IN PLACE (additive).
# QEMU's device models (nvme-io.c, femu.c, ...) have no standalone entry point: they need a full system-emulator build.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

EDK2="$SRC/roms/edk2"
BROTLI="$EDK2/BaseTools/Source/C/BrotliCompress/brotli"
MBED="$EDK2/CryptoPkg/Library/MbedTlsLib/mbedtls"
JANSSON="$EDK2/RedfishPkg/Library/JsonLib/jansson"
ONIG="$EDK2/MdeModulePkg/Universal/RegularExpressionDxe/oniguruma"
FEMU="$SRC/hw/femu"
B="$SRC/mayhem/build"          # gitignored by upstream's `build/` rule, so `git clean -ffdX` removes it
OUT="$SRC"                     # fuzz binaries land at /mayhem/<target>
mkdir -p "$B"

# Library flags: sanitized + DWARF<=3 + SanCov on the library itself (not only the harness TU).
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
TEST_CFLAGS="-O2 $COVERAGE_FLAGS"

# cmake_lib <name> <srcdir> <cflags> <build-dir-suffix> [cmake args...]  ->  static libs under $B/<name><suffix>
cmake_lib() {
  local name="$1" srcdir="$2" cflags="$3" suffix="$4"; shift 4
  # CMake resets its cache (dropping our -D options) when the resolved compiler path changes, e.g. when the
  # image build ran under the ccache masquerade dir and a later re-run resolves clang plainly: start fresh then.
  if [ -f "$B/$name$suffix/CMakeCache.txt" ] && \
     ! grep -q "^CMAKE_C_COMPILER:[A-Z]*=$(command -v "$CC")\$" "$B/$name$suffix/CMakeCache.txt"; then
    rm -rf "$B/$name$suffix"
  fi
  cmake -S "$srcdir" -B "$B/$name$suffix" -G Ninja \
    -DCMAKE_BUILD_TYPE= -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$cflags" -DCMAKE_CXX_FLAGS="$cflags" \
    -DBUILD_SHARED_LIBS=OFF "$@" >"$B/$name$suffix.cmake.log" 2>&1 \
    || { cat "$B/$name$suffix.cmake.log"; exit 1; }
  cmake --build "$B/$name$suffix" -j"$MAYHEM_JOBS" >"$B/$name$suffix.build.log" 2>&1 \
    || { tail -50 "$B/$name$suffix.build.log"; exit 1; }
}

build_libs() {   # <suffix> <cflags>
  local suffix="$1" cflags="$2"
  cmake_lib brotli "$BROTLI" "$cflags" "$suffix" -DBROTLI_DISABLE_TESTS=ON -DBROTLI_BUNDLED_MODE=OFF
  cmake_lib mbedtls "$MBED" "$cflags -DMBEDTLS_PKCS7_C" "$suffix" -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF \
    -DMBEDTLS_FATAL_WARNINGS=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON
  cmake_lib jansson "$JANSSON" "$cflags" "$suffix" -DJANSSON_BUILD_DOCS=OFF -DJANSSON_EXAMPLES=OFF \
    -DJANSSON_WITHOUT_TESTS=ON -DJANSSON_BUILD_SHARED_LIBS=OFF
  cmake_lib onig "$ONIG" "$cflags" "$suffix" -DENABLE_POSIX_API=OFF
}

# 1) Sanitized + instrumented libraries.
build_libs "" "$FUZZ_CFLAGS"

# 2) Harnesses: each linked twice (libFuzzer binary + run-once standalone reproducer), plus the LSan-off hook.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"

BROTLI_LIBS=("$B/brotli/libbrotlidec-static.a" "$B/brotli/libbrotlicommon-static.a")
MBED_LIBS=("$B/mbedtls/library/libmbedx509.a" "$B/mbedtls/library/libmbedcrypto.a")
MBED_FUZZ="$MBED/programs/fuzz"

# link_harness <target> <compiler> <extra compile args...> -- <sources> -- <libs>
link_harness() {
  local target="$1" comp="$2"; shift 2
  local cargs=() srcs=() libs=() mode=cargs
  for a in "$@"; do
    if [ "$a" = "--" ]; then
      case $mode in cargs) mode=srcs ;; srcs) mode=libs ;; esac; continue
    fi
    case $mode in cargs) cargs+=("$a") ;; srcs) srcs+=("$a") ;; libs) libs+=("$a") ;; esac
  done
  $comp $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${cargs[@]}" "${srcs[@]}" "$B/lsan_off.o" "${libs[@]}" $LIB_FUZZING_ENGINE -o "$OUT/$target"
  $comp $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${cargs[@]}" "${srcs[@]}" "$B/lsan_off.o" "$B/standalone_main.o" "${libs[@]}" -o "$OUT/$target-standalone"
}

# FEMU's own modules: the stub osdep.h first on the include path, so "qemu/osdep.h" does not need QEMU.
FEMU_INC=(-I"$FEMU/tests" -I"$SRC" -I"$FEMU/nand" -I"$FEMU/kvssd")
femu_obj() {   # <src.c> <obj-name>   instrumented like the libraries: sanitized, DWARF<=3, SanCov
  $CC $FUZZ_CFLAGS -std=gnu11 "${FEMU_INC[@]}" -c "$1" -o "$B/femu_$2.o"
}
femu_obj "$FEMU/kvssd/kv-lsm.c" kv_lsm
femu_obj "$FEMU/kvssd/kv-pack.c" kv_pack
femu_obj "$FEMU/nand/nand-media.c" nand_media
femu_obj "$FEMU/nand/onfi.c" onfi

link_harness fuzz_kv_lsm "$CC" -std=gnu11 "${FEMU_INC[@]}" -- "$SRC/mayhem/fuzz_kv_lsm/harness.c" -- "$B/femu_kv_lsm.o"
link_harness fuzz_kv_pack "$CC" -std=gnu11 "${FEMU_INC[@]}" -- "$SRC/mayhem/fuzz_kv_pack/harness.c" -- "$B/femu_kv_pack.o"
link_harness fuzz_nand_media "$CC" -std=gnu11 "${FEMU_INC[@]}" -- "$SRC/mayhem/fuzz_nand_media/harness.c" -- "$B/femu_nand_media.o"
link_harness fuzz_onfi "$CC" -std=gnu11 "${FEMU_INC[@]}" -- "$SRC/mayhem/fuzz_onfi/harness.c" -- "$B/femu_onfi.o"

link_harness fuzz_brotli_decode "$CC" -I"$BROTLI/c/include" -- "$BROTLI/c/fuzz/decode_fuzzer.c" -- "${BROTLI_LIBS[@]}"

# MBEDTLS_PKCS7_C is off in the default config (the pkcs7 harness is an empty stub without it): enable via -D, no tree edit.
for t in x509crt x509crl x509csr pkcs7 pubkey; do
  link_harness "fuzz_$t" "$CC" -I"$MBED/include" -DMBEDTLS_PKCS7_C -- "$MBED_FUZZ/fuzz_$t.c" -- "${MBED_LIBS[@]}"
done
link_harness fuzz_privkey "$CC" -I"$MBED/include" -I"$MBED_FUZZ" -- "$MBED_FUZZ/fuzz_privkey.c" "$MBED_FUZZ/common.c" \
  -- "$B/mbedtls/library/libmbedtls.a" "${MBED_LIBS[@]}"

link_harness fuzz_jansson_load_dump "$CXX" -I"$B/jansson/include" -- "$JANSSON/test/ossfuzz/json_load_dump_fuzzer.cc" -- "$B/jansson/lib/libjansson.a"

link_harness fuzz_onig "$CXX" -I"$ONIG/src" -- "$ONIG/harnesses/libfuzzer-onig.cpp" -- "$B/onig/libonig.a"

# 3) Known-answer test programs, built with the project's NORMAL flags against clean (unsanitized) libraries.
build_libs "-test" "$TEST_CFLAGS"
T="$SRC/mayhem/tests"
mkdir -p "$B/tests"
$CC $TEST_CFLAGS -I"$BROTLI/c/include" "$T/test_brotli.c" "$B/brotli-test/libbrotlidec-static.a" "$B/brotli-test/libbrotlicommon-static.a" -o "$B/tests/test_brotli"
$CC $TEST_CFLAGS -I"$MBED/include" "$T/test_mbedtls.c" "$B/mbedtls-test/library/libmbedx509.a" "$B/mbedtls-test/library/libmbedcrypto.a" -o "$B/tests/test_mbedtls"
$CC $TEST_CFLAGS -I"$B/jansson-test/include" "$T/test_jansson.c" "$B/jansson-test/lib/libjansson.a" -o "$B/tests/test_jansson"
$CC $TEST_CFLAGS -I"$ONIG/src" "$T/test_onig.c" "$B/onig-test/libonig.a" -o "$B/tests/test_onig"

# FEMU's own unit tests (hw/femu/tests/unit, TAP output), built as hw/femu/tests/Makefile does but into $B/tests.
FEMU_TEST_CFLAGS="-O2 -std=gnu11 $COVERAGE_FLAGS"
U="$FEMU/tests/unit"
$CC $FEMU_TEST_CFLAGS "${FEMU_INC[@]}" -c "$FEMU/nand/nand-media.c" -o "$B/tests/nand-media.o"
$CC $FEMU_TEST_CFLAGS "${FEMU_INC[@]}" -c "$FEMU/nand/onfi.c" -o "$B/tests/onfi.o"
$CC $FEMU_TEST_CFLAGS "${FEMU_INC[@]}" "$U/test-nand-media.c" "$B/tests/nand-media.o" -o "$B/tests/test_femu_nand_media"
$CC $FEMU_TEST_CFLAGS "${FEMU_INC[@]}" "$U/test-onfi-timing.c" "$B/tests/nand-media.o" "$B/tests/onfi.o" -o "$B/tests/test_femu_onfi_timing"
$CC $FEMU_TEST_CFLAGS "${FEMU_INC[@]}" "$U/test-kv-lsm.c" -o "$B/tests/test_femu_kv_lsm"
$CC $FEMU_TEST_CFLAGS "${FEMU_INC[@]}" "$U/test-kv-pack.c" -o "$B/tests/test_femu_kv_pack"
