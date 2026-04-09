#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

keys=${1:-tests/data/keys}
out="$keys/pub"
rm -rf "$out"
mkdir -p "$out"
pairs="$out/pairs.tsv"
: > "$pairs"
pass=keytrawl-test

dss_line() { # private PEM -> ssh-dss line
    openssl pkey -in "$1" -text -noout | python3 -I -c '
import base64, re, struct, sys
t = sys.stdin.read()
def num(name):
    m = re.search(name + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", t)
    return int(re.sub(r"[\s:]", "", m.group(1)), 16)
def s(b): return struct.pack(">I", len(b)) + b
def mp(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return s(b)
blob = s(b"ssh-dss") + mp(num("P")) + mp(num("Q")) + mp(num("G")) + mp(num("pub"))
print("ssh-dss " + base64.b64encode(blob).decode() + " test@keytrawl")'
}

forms() { # private PEM, family, base -> the public files of the key
    local k=$1 fam=$2 b=$3
    openssl pkey -in "$k" -pubout -out "$b.spki.pem"
    openssl pkey -in "$k" -pubout -outform DER -out "$b.spki.der"
    openssl req -x509 -key "$k" -subj /CN=keytrawl-test -days 1 -out "$b.crt.pem" 2>/dev/null
    openssl x509 -in "$b.crt.pem" -outform DER -out "$b.crt.der"
    [ "$fam" = rsa ] && openssl rsa -in "$k" -RSAPublicKey_out -out "$b.rsapub.pem" 2>/dev/null
    if [ "$fam" = dsa ]; then dss_line "$k" > "$b.ssh.pub"; else ssh-keygen -y -f "$k" > "$b.ssh.pub"; fi
}

for k in "$keys"/*.p8.pem; do
    name=${k##*/}
    mat=${name%.p8.pem}
    fam=$(awk -F'\t' -v f="$name" '$1 == f {print $3}' "$keys/manifest.tsv")
    chmod 600 "$k"
    forms "$k" "$fam" "$out/$mat"
    for f in "$keys/$mat".{p8.pem,p8.der,trad.pem,trad.der}; do
        [ -f "$f" ] || continue
        for p in "$out/$mat".*; do echo -e "${f##*/}\tpub/${p##*/}\t$fam" >> "$pairs"; done
    done
done

for k in "$keys"/ssh-*; do
    name=${k##*/}
    fam=$(awk -F'\t' -v f="$name" '$1 == f {print $3}' "$keys/manifest.tsv")
    pw=
    case $name in *-enc-*) pw=$pass ;; esac
    ssh-keygen -y -P "$pw" -f "$k" > "$out/$name.ssh.pub"
    [ "$fam" = ed25519 ] || ssh-keygen -e -m PKCS8 -f "$out/$name.ssh.pub" > "$out/$name.spki.pem"
    for p in "$out/$name".*; do echo -e "$name\tpub/${p##*/}\t$fam" >> "$pairs"; done
done
echo "pairs: $(wc -l < "$pairs")"
