#!/usr/bin/env bash
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <keytrawl cli> file..." >&2; exit 2; }
cli=$1
shift
run() { local chunk=$1; shift; "$cli" -a -c "$chunk" "$@" || [ $? -eq 3 ]; }
a=$(run 65536 "$@" | sha256sum)
b=$(run 65536 "$@" | sha256sum)
c=$(run 4093 "$@" | sha256sum)
if [ "$a" != "$b" ] || [ "$a" != "$c" ]; then
    echo "outputs differ: $a / $b / $c" >&2
    exit 1
fi
echo "deterministic: $(run 65536 "$@" | wc -l) findings, sha256 ${a%% *}"
