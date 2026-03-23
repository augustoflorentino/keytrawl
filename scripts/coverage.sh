#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=$root/build/cov
cmake -S "$root" -B "$build" -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF \
    -DKEYTRAWL_BUILD_TESTS=ON "-DCMAKE_C_FLAGS=-fprofile-instr-generate -fcoverage-mapping" > /dev/null
cmake --build "$build" > /dev/null
rm -f "$build/test.profraw"
(cd "$build" && LLVM_PROFILE_FILE=test.profraw ./test_keytrawl > /dev/null)
llvm-profdata merge -o "$build/test.profdata" "$build/test.profraw"
llvm-cov report "$build/test_keytrawl" -instr-profile="$build/test.profdata" "$root"/src/*.c
