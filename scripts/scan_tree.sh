#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

[ $# -ge 3 ] || { echo "usage: $0 <keytrawl cli> <out> dir..." >&2; exit 2; }
cli=$1
out=$2
shift 2
start=$(date +%s)
find "$@" -type f -readable -print0 2> /dev/null | xargs -0 -n 500 "$cli" -a > "$out.tsv" 2> "$out.err" || true
find "$@" -type f -readable -printf '%s\n' 2> /dev/null \
    | awk -v s="$(( $(date +%s) - start ))" '{b += $1; n++} END {printf "%d files, %.1f MB, %d s\n", n, b / 1048576, s}'
echo "$(wc -l < "$out.tsv") findings, $(wc -l < "$out.err") error lines"
cut -f5,6 "$out.tsv" | sort | uniq -c | sort -rn
