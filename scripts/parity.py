#!/usr/bin/env python3
"""Parity of keytrawl with the secrets analyzer of fwtriage, its origin.

Runs both on the same files, the ones fwtriage unpacks from its test corpus and from firmware
images, plus the baits of its unit tests and randomly generated lines, and compares what both can
report. Findings only keytrawl can make (bare DER, ASIA keys, other vendors) are counted apart.

usage: parity.py --fwtriage DIR --lib libkeytrawl.so [--images IMG...] [--random N] [--seed S]
"""

import argparse
import ctypes
import random
import re
import sys
from collections import Counter
from pathlib import Path

ENCRYPTED, IN_BINARY = 0x01, 0x02
PEM_KINDS = range(1, 7)
AWS, WIFI, AUTHORIZED = 12, 17, 18
CONF = {3: "confirmed", 2: "likely", 1: "indicator"}

class Lib:
    def __init__(self, path):
        lib = ctypes.CDLL(path)
        self.lib = lib
        self.callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        for name, restype in (
            ("ktw_finding_kind", ctypes.c_int),
            ("ktw_finding_confidence", ctypes.c_int),
            ("ktw_finding_flags", ctypes.c_uint),
            ("ktw_finding_offset", ctypes.c_uint64),
            ("ktw_finding_length", ctypes.c_uint64),
            ("ktw_finding_line", ctypes.c_uint64),
            ("ktw_finding_evidence", ctypes.c_char_p),
        ):
            getattr(lib, name).restype = restype
            getattr(lib, name).argtypes = [ctypes.c_void_p]
        catalog, scanner = ctypes.c_void_p(), ctypes.c_void_p()
        assert lib.ktw_catalog_create(0x0F, None, None, None, ctypes.byref(catalog)) == 0
        assert lib.ktw_catalog_compile(catalog) == 0
        assert lib.ktw_scanner_create(catalog, None, None, None, ctypes.byref(scanner)) == 0
        self.scanner = scanner

    def scan(self, path: str, data: bytes) -> list[dict]:
        lib, found = self.lib, []

        def on_finding(_ctx, f):
            found.append(
                {
                    "kind": lib.ktw_finding_kind(f),
                    "confidence": lib.ktw_finding_confidence(f),
                    "flags": lib.ktw_finding_flags(f),
                    "offset": lib.ktw_finding_offset(f),
                    "length": lib.ktw_finding_length(f),
                    "line": lib.ktw_finding_line(f),
                    "evidence": lib.ktw_finding_evidence(f).decode("utf-8", "replace"),
                }
            )
            return 0

        callback = self.callback_type(on_finding)
        name = path.encode()
        assert lib.ktw_scanner_reset(self.scanner, name, ctypes.c_size_t(len(name))) == 0
        assert lib.ktw_feed(self.scanner, data, ctypes.c_size_t(len(data)), callback, None) == 0
        assert lib.ktw_finish(self.scanner, callback, None) == 0
        return found

def python_findings(secrets, entry) -> set[tuple]:
    """What fwtriage's _scan reports, before it groups indicators of one binary (presentation)."""
    out = set()
    for match in secrets.PRIVATE_KEY.finditer(entry.data):
        f = secrets._private_key(entry, "x", match)
        if f is not None:
            out.add(("pem", f.location.offset, f.evidence.excerpt, f.rule, f.confidence.name.lower()))
    for match in secrets.CLOUD_KEY.finditer(entry.data):
        f = secrets._cloud_key(entry, "x", match)
        out.add(("aws", f.location.offset, f.evidence.excerpt, f.rule, f.confidence.name.lower()))
    if secrets._is_wifi_config(entry):
        for match in secrets.WIFI_KEY.finditer(entry.data):
            f = secrets._wifi_key(entry, "x", match)
            out.add(("wifi", f.location.line, f.evidence.excerpt, f.rule, f.confidence.name.lower()))
    if entry.name in ("authorized_keys", "authorized_keys2"):
        for f in secrets._authorized_keys(entry, "x"):
            out.add(("ak", f.location.line, clip(f.evidence.excerpt), f.rule, f.confidence.name.lower()))
    return out

LONG_TOKENS = Counter()
CUT = "<cut by fwtriage>"
TOKEN_MAX = 99  # bytes of a token that keytrawl keeps for the evidence of authorized_keys

def clip(excerpt: str) -> str:
    """keytrawl keeps the first TOKEN_MAX bytes of the tokens it quotes: declared divergence."""
    if excerpt.endswith("\u2026"):  # fwtriage's Finding cuts every excerpt at 200 characters
        LONG_TOKENS["excerpts cut by fwtriage"] += 1
        return CUT
    match = re.fullmatch(r"(.*?) key, comment '(.*)'", excerpt, re.S)
    if match is None or max(len(match[1]), len(match[2])) <= TOKEN_MAX:
        return excerpt
    LONG_TOKENS["findings"] += 1
    return f"{match[1][:TOKEN_MAX]} key, comment '{match[2][:TOKEN_MAX]}'"

def lib_findings(found: list[dict]) -> tuple[set[tuple], Counter]:
    out, extra = set(), Counter()
    for f in found:
        kind, conf = f["kind"], CONF[f["confidence"]]
        if kind in PEM_KINDS:
            rule = "FWT-SEC-002" if f["flags"] & ENCRYPTED else "FWT-SEC-001"
            out.add(("pem", f["offset"], f["evidence"], rule, conf))
        elif kind == AWS and f["evidence"].startswith("AKIA"):
            out.add(("aws", f["offset"], f["evidence"], "FWT-SEC-003", conf))
        elif kind == WIFI:
            out.add(("wifi", f["line"], f"line {f['line']}: {f['evidence']}", "FWT-SEC-004", conf))
        elif kind == AUTHORIZED:
            out.add(("ak", f["line"], f["evidence"], "FWT-SEC-005", conf))
        else:
            extra[kind] += 1
    return out, extra

def unicode_separators(data: bytes) -> bool:
    """Whether decoding gives characters Python splits on, or replaces, beyond ASCII."""
    text = data.decode(errors="replace")
    return any(ord(ch) >= 0x80 and (ch.isspace() or ch == "\ufffd" or ch in "\u2028\u2029") for ch in text)

class Tally:
    def __init__(self):
        self.files = 0
        self.bytes = 0
        self.same = Counter()
        self.confidence = Counter()
        self.only_python = []
        self.only_lib = []
        self.extra = Counter()
        self.non_ascii = Counter()

    def compare(self, source, entry, py: set[tuple], lib: set[tuple]):
        self.files += 1
        self.bytes += len(entry.data)
        cut = {t[1] for t in py if t[0] == "ak" and t[2] == CUT}
        lib = {("ak", t[1], CUT, *t[3:]) if t[0] == "ak" and t[1] in cut else t for t in lib}
        core = lambda s: {t[:3] for t in s}  # noqa: E731
        both = core(py) & core(lib)
        if core(py) != core(lib) and unicode_separators(entry.data) and any(t[0] == "ak" for t in py | lib):
            self.non_ascii["entries"] += 1
            self.non_ascii["findings"] += len(py ^ lib)
            return
        for key in both:
            self.same[key[0]] += 1
            p = next(t for t in py if t[:3] == key)
            k = next(t for t in lib if t[:3] == key)
            if p[3:] != k[3:]:
                self.confidence[(key[0], p[3], p[4], k[3], k[4])] += 1
        for t in py:
            if t[:3] not in both:
                self.only_python.append((source, entry.path, t))
        for t in lib:
            if t[:3] not in both:
                self.only_lib.append((source, entry.path, t))

    def report(self):
        print(f"files {self.files}, {self.bytes / 1e6:.1f} MB")
        print("matched:", dict(self.same))
        for key, n in sorted(self.confidence.items()):
            print(f"  same finding, other rule or confidence: {key} x{n}")
        for label, items in (("only fwtriage", self.only_python), ("only keytrawl", self.only_lib)):
            by_class = Counter(t[0] for _, _, t in items)
            print(f"{label}: {len(items)} {dict(by_class)}")
            for cls in by_class:
                for item in [i for i in items if i[2][0] == cls][:8]:
                    print("  ", item)
        print("keytrawl extensions by kind:", dict(self.extra))
        print("authorized_keys with non-ASCII bytes, set apart:", dict(self.non_ascii))
        print("authorized_keys tokens clipped to", TOKEN_MAX, "bytes:", dict(LONG_TOKENS))

def corpus_entries(fwtriage: Path):
    sys.path.insert(0, str(fwtriage))
    from tests.corpus.scenarios import SCENARIOS

    for scenario in SCENARIOS:
        yield from unpacked(f"corpus:{scenario.name}", scenario.build(), scenario.limits)

def unpacked(source, buffer, limits=None):
    from fwtriage.engine.unpacker import Unpacker
    from fwtriage.formats import REGISTRY
    from fwtriage.model import Budget, Policy

    budget = Budget(limits or Policy().limits)
    result = Unpacker(REGISTRY, budget).run(buffer, source)
    for located in result.filesystems:
        for entry in located.filesystem.files():
            yield source, entry

def file_entries(paths):
    """Plain files, each one entry under its own path."""
    from fwtriage.model.vfs import Entry

    for path in paths:
        yield "file", Entry(str(path), "file", 0o644, 0, 0, Path(path).read_bytes(), None)

def bait_entries():
    from fwtriage.model.vfs import Entry

    baits = [
        ("/usr/lib/libparse.so", b"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n"),
        ("/etc/config/wireless", b"config wifi-iface\n\toption key '/etc/wifi.key'\n"),
        ("/usr/share/doc/example.txt", b"wpa_passphrase=documentation-example\n"),
    ]
    for path, data in baits:
        yield "bait", Entry(path, "file", 0o644, 0, 0, data, None)

PIECES_WIFI = [b"option", b"option key", b"option\tkey", b"wpa_passphrase", b"psk", b"psk=", b" ", b"\t", b"=",
               b"==", b"'", b'"', b"/", b"$", b"abcdefgh", b"x" * 7, b"s3cret", b"\n", b"\r", b"y" * 60, b"#"]
PIECES_TEXT = [b"AKIAIOSFODNN7EXAMPLE", b"AKIA", b"0123456789ABCDEF", b" ", b"_", b"x", b"\n", b"-----BEGIN ",
               b"RSA PRIVATE KEY-----\n", b"-----END RSA PRIVATE KEY-----", b"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX\n",
               b"Proc-Type: 4,ENCRYPTED\n", b"OPENSSH PRIVATE KEY-----\n", b"AAAAAAAAAAAAAAAAAAAA\n", b"\r\n"]
PIECES_AK = [b"ssh-ed25519", b" ", b"\t", b"AAAAC3NzaC1lZDI1NTE5AAAAIExJeoA/ZHc5NgshcUXHRYuKDCzlpGSQHZ1329ciZfSP",
             b"me@host", b"#", b"\n", b"\r", b"command=\"a b\"", b"ssh-rsa", b"\x0b", b"\x0c", b"\x1c", b"\xc2\x85"]

def wifi_line(rng) -> bytes:
    pick = rng.choice
    lead = pick([b"", b" ", b"\t", b"  \t"])
    key = pick([b"option key", b"option\t key", b"wpa_passphrase", b"psk", b"optionkey", b"ps", b"option  key"])
    sep = b"".join(pick([b" ", b"\t", b"="]) for _ in range(rng.randint(0, 12)))
    quote = pick([b"", b"'", b'"'])
    value = bytes(pick(b"abcXYZ019=/$-_.'\" \t\r") for _ in range(rng.choice([0, 1, 3, 6, 7, 8, 9, 20, 62, 63, 64, 70])))
    tail = pick([b"", b" ", b"\t \t", b"x", b"#"])
    return lead + key + sep + quote + value + pick([b"", quote]) + tail

def random_entries(count, seed):
    from fwtriage.model.vfs import Entry

    rng = random.Random(seed)
    for i in range(count // 2):
        data = b"\n".join(wifi_line(rng) for _ in range(rng.randint(1, 6))) + rng.choice([b"", b"\n"])
        yield "random", Entry(rng.choice(["/etc/config/wireless", "/x/wpa_supplicant-wlan0.conf"]), "file", 0o644, 0,
                              0, data, None)
    kinds = [("/etc/config/wireless", PIECES_WIFI), ("/x/hostapd.conf", PIECES_WIFI), ("/x/notes.txt", PIECES_TEXT),
             ("/root/.ssh/authorized_keys", PIECES_AK)]
    for i in range(count):
        path, pieces = kinds[i % len(kinds)]
        data = b"".join(rng.choice(pieces) for _ in range(rng.randint(1, 40)))
        yield "random", Entry(path, "file", 0o644, 0, 0, data, None)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fwtriage", type=Path, required=True)
    parser.add_argument("--lib", required=True)
    parser.add_argument("--images", nargs="*", default=[])
    parser.add_argument("--files", nargs="*", default=[])
    parser.add_argument("--random", type=int, default=0)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    sys.path.insert(0, str(args.fwtriage / "src"))
    from fwtriage.analyzers import secrets

    lib, tally = Lib(args.lib), Tally()
    sources = [corpus_entries(args.fwtriage), bait_entries(), random_entries(args.random, args.seed)]
    sources.append(file_entries(args.files))
    sources += [unpacked(f"image:{Path(p).name[:12]}", Path(p).read_bytes()) for p in args.images]
    for source in sources:
        for name, entry in source:
            found, extra = lib_findings(lib.scan(entry.path, entry.data))
            tally.extra.update(extra)
            tally.compare(name, entry, python_findings(secrets, entry), found)
    tally.report()

if __name__ == "__main__":
    main()
