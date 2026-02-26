#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

out=${1:-tests/data/keys}
rm -rf "$out"
mkdir -p "$out"
manifest="$out/manifest.tsv"
: > "$manifest"
pass=keytrawl-test
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

genkey() { # alg -> unencrypted PKCS#8 PEM on stdout
    case $1 in
    rsa*) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${1#rsa}" 2>/dev/null ;;
    ec256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 ;;
    ec384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 ;;
    ed25519) openssl genpkey -algorithm ED25519 ;;
    dsa*)
        openssl genpkey -genparam -algorithm DSA -pkeyopt "dsa_paramgen_bits:${1#dsa}" -out "$work/p.pem" 2>/dev/null
        openssl genpkey -paramfile "$work/p.pem" ;;
    esac
}

family() { case $1 in rsa*) echo rsa ;; ec*) echo ec ;; dsa*) echo dsa ;; *) echo "$1" ;; esac; }

traditional() { # family in out [cipher]
    local extra=()
    [ "$1" = rsa ] && extra+=(-traditional)
    [ $# -eq 4 ] && extra+=("-$4" -passout "pass:$pass")
    openssl "$1" -in "$2" "${extra[@]}" -out "$3" 2>/dev/null
}

emit() { echo -e "$1\t$2\t$3" >> "$manifest"; }

pem_kind() { case $1 in rsa) echo pem-rsa-private-key ;; ec) echo pem-ec-private-key ;; dsa) echo pem-dsa-private-key ;; esac; }
der_kind() { case $1 in rsa) echo der-rsa-private-key ;; ec) echo der-ec-private-key ;; dsa) echo der-dsa-private-key ;; esac; }

for round in 1 2 3; do
    for alg in rsa1024 rsa2048 rsa3072 rsa4096 ec256 ec384 dsa1024 dsa2048 ed25519; do
        fam=$(family "$alg")
        base="$out/$alg-$round"
        genkey "$alg" > "$work/k.pem"
        cp "$work/k.pem" "$base.p8.pem"; emit "${base##*/}.p8.pem" pem-pkcs8-private-key "$fam"
        openssl pkey -in "$work/k.pem" -outform DER -out "$base.p8.der"
        emit "${base##*/}.p8.der" der-pkcs8-private-key "$fam"
        openssl pkcs8 -topk8 -in "$work/k.pem" -passout "pass:$pass" -out "$base.p8enc.pem"
        emit "${base##*/}.p8enc.pem" pem-pkcs8-encrypted-private-key none
        openssl pkcs8 -topk8 -in "$work/k.pem" -passout "pass:$pass" -outform DER -out "$base.p8enc.der"
        emit "${base##*/}.p8enc.der" der-pkcs8-encrypted-private-key none
        [ "$fam" = ed25519 ] && continue
        traditional "$fam" "$work/k.pem" "$base.trad.pem"; emit "${base##*/}.trad.pem" "$(pem_kind "$fam")" "$fam"
        traditional "$fam" "$work/k.pem" "$base.legacyenc.pem" aes128
        emit "${base##*/}.legacyenc.pem" "$(pem_kind "$fam")" "$fam"
        der=(-outform DER)
        [ "$fam" = rsa ] && der+=(-traditional)
        openssl "$fam" -in "$base.trad.pem" "${der[@]}" -out "$base.trad.der" 2>/dev/null
        emit "${base##*/}.trad.der" "$(der_kind "$fam")" "$fam"
    done
    for spec in "rsa 2048 rsa" "ecdsa 256 ec" "ecdsa 384 ec" "ed25519 0 ed25519"; do
        set -- $spec
        for enc in plain enc; do
            f="$out/ssh-$1-$2-$enc-$round"
            [ "$enc" = enc ] && pw=$pass || pw=
            if [ "$2" = 0 ]; then bits=(); else bits=(-b "$2"); fi
            ssh-keygen -q -t "$1" "${bits[@]}" -N "$pw" -C "test@keytrawl" -f "$f"
            rm -f "$f.pub"
            emit "${f##*/}" pem-openssh-private-key "$3"
        done
    done
done
echo "keys: $(wc -l < "$manifest")"
