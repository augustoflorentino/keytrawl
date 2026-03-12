"""Throughput of fwtriage's secrets scan, the Python that keytrawl replaces (G9).

usage, from a fwtriage checkout:
    uv run python <keytrawl>/bench/python_bench.py file

The file is repeated up to 256 MB, as bench.c does with it, and scanned as one entry by
fwtriage.analyzers.secrets._scan. Compare with the "single" line of `keytrawl_bench file`.
"""

import sys
import time

from fwtriage.analyzers import secrets
from fwtriage.model import Entry, EntryKind

INPUT_SIZE = 256 << 20
MB = 1024 * 1024

def load(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read(INPUT_SIZE)
    if not data:
        raise SystemExit(f"python_bench: {path}: empty")
    return (data * (INPUT_SIZE // len(data) + 1))[:INPUT_SIZE] if len(data) < INPUT_SIZE else data

def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python_bench.py file")
    data = load(sys.argv[1])
    entry = Entry("/bench/input", EntryKind.FILE, 0o644, 0, 0, data)
    start = time.perf_counter()
    found = secrets._scan(entry, "bench")
    seconds = time.perf_counter() - start
    print(f"python   {len(data) / MB / seconds:.0f} MB/s over {len(data) / MB:.0f} MB, {len(found)} findings")

if __name__ == "__main__":
    main()
