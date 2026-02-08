#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/keytrawl/keytrawl.h}
mkdir -p "$(dirname "$out")"

{
    cat "$root/include/keytrawl/keytrawl.h"
    echo
    echo "#if defined(KTW_IMPLEMENTATION) && !defined(KTW_IMPLEMENTATION_DONE)"
    echo "#define KTW_IMPLEMENTATION_DONE"
    for src in "$root"/src/*.h "$root"/src/*.c; do
        [ -f "$src" ] && grep -v '^#include "' "$src"
    done
    echo "#endif"
} > "$out"
echo "$out"
