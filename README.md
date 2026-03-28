# keytrawl

Streaming secret finder for raw bytes: private keys, cloud tokens and configuration secrets, each
validated before it is reported.

keytrawl looks at bytes, not at text files: firmware images, executables, memory dumps, disk
images. It runs every pattern in one pass of an Aho-Corasick automaton, takes the input in pieces
of any size, and finds a secret even when it straddles two pieces. A finding is confirmed only
when its structure checks out; what is only shaped like a secret is reported as an indicator.

## What it finds

| Kind | How it is checked | Confidence |
|---|---|---|
| PEM private keys: RSA, EC, DSA, OpenSSH, PKCS#8, encrypted PKCS#8 | base64 decoded on the fly; the DER walked against its ASN.1 schema (RFC 8017, RFC 5915, RFC 5208, RFC 5958); OpenSSH `openssh-key-v1` framing | confirmed when the structure holds, indicator otherwise |
| Bare DER private keys: PKCS#1 RSA, DSA, SEC 1 EC, PKCS#8, PKCS#8 encrypted with PBES2 | same schemas, plus the key inside a PKCS#8 envelope and the relations of RSA parameters (odd modulus, primes of half its size) | confirmed |
| AWS access key ID `AKIA`/`ASIA` | prefix and alphabet ([IAM identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)); marks a 40-character secret key in the 240 bytes after it (`KTW_CHECK_PAIRED`) | likely |
| GitHub tokens `ghp_` `gho_` `ghu_` `ghs_` `ghr_` | CRC32 of the token against its last 6 characters ([token formats](https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/)); a failed checksum reports nothing | confirmed |
| GitHub `github_pat_` | length and alphabet of both parts | likely |
| Google API key `AIza` | length 39 and alphabet; no published specification | likely |
| Slack `xoxb-` `xoxp-` `xoxa-` `xoxr-` `xoxs-` | numeric segments and final part ([token types](https://api.slack.com/authentication/token-types)) | likely |
| Stripe `sk_live_` | length and alphabet ([API keys](https://docs.stripe.com/keys)) | likely |
| Wi-Fi passphrase | in `/etc/config/wireless`, `hostapd*.conf`, `wpa_supplicant*.conf`: `option key`, `wpa_passphrase`, `psk` | likely |
| `authorized_keys` line | key type, base64 and the SSH wire format of the public key | confirmed when valid, indicator otherwise |
| Your own literals | your validator callback decides | yours |

Private keys inside an executable (ELF, or a `.so` in the stream name) are reported as indicators
with `KTW_FLAG_IN_BINARY`: those are almost always test vectors. Encrypted keys carry
`KTW_FLAG_ENCRYPTED`. keytrawl never decrypts anything and never touches the network.

The evidence never holds the secret: at most its first 4 and last 4 bytes (`AKIA…MPLE`).

## Usage

```c
static int print_finding(void *ctx, const ktw_finding_t *f)
{
    printf("%s at %llu: %s\n", ktw_finding_name(f), (unsigned long long)ktw_finding_offset(f),
           ktw_finding_evidence(f));
    return 0; /* nonzero stops the scan */
}

ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &catalog); /* once */
ktw_catalog_compile(catalog);                                  /* read-only from here on */
ktw_scanner_create(catalog, NULL, NULL, NULL, &scanner);       /* one per stream or thread */
ktw_scanner_reset(scanner, "/etc/config/wireless", 20);        /* the name enables Wi-Fi and authorized_keys */
while ((n = fread(buf, 1, sizeof buf, in)) > 0)
    ktw_feed(scanner, buf, n, print_finding, NULL);
ktw_finish(scanner, print_finding, NULL);
```

Complete programs: [`examples/basic.c`](examples/basic.c) and the command-line scanner
[`examples/keytrawl.c`](examples/keytrawl.c), which prints one tab-separated line per finding:

```
$ keytrawl creds
creds	20	20	0	aws-access-key-id	likely	none	AKIA…MPLE
$ keytrawl -a /usr/lib/libgnutls.so.30.42.0
/usr/lib/libgnutls.so.30.42.0	1714080	155	0	pem-pkcs8-private-key	indicator	ed448	-----BEGIN PRIVATE KEY----- (155 bytes)
...
```

The header [`include/keytrawl/keytrawl.h`](include/keytrawl/keytrawl.h) is the API reference.
Conventions:

- every function that can fail returns `KTW_OK` or an error code; `ktw_strerror` describes it
- what `ktw_x_create` returns is released only by `ktw_x_destroy`, which accepts `NULL`
- functions never take ownership of their arguments; returned pointers belong to the library
- pass your own allocator to the create functions, or `NULL` for `malloc`/`free`
- `ktw_feed` and `ktw_finish` never allocate; a scanner holds about 4 KB whatever the input size

## Numbers

Measured on 2026-03-24, AMD Ryzen 7 5700G, GCC 16.2, release build, on a machine busy with other
work. Every number has a script.

| Measure | Result | Script |
|---|---|---|
| One thread, random bytes | 1065 MB/s | `bench/bench.c` |
| One thread, `/usr/lib` concatenated | 1042 MB/s | `bench/bench.c file` |
| Four threads, one catalog | 3.94x one thread by CPU time | `bench/bench.c` |
| fwtriage's Python scan on the same bytes | 33 to 53 MB/s; keytrawl is 11x to 21x faster | `bench/python_bench.py` |
| 1 GB of `-----BEGIN ` | linear (4.07x the time of 256 MB), 0 allocations | `bench/bench.c` |
| False positives in `/usr/bin` and `/usr/lib` (14 GB) and 3 OpenWrt rootfs | 0 false confirmed; 0.46 false indications per 100 MB, all documentation examples of AWS keys | `scripts/scan_tree.sh`, reviewed by hand |
| Line coverage of `src/` by the tests | 95% | `scripts/coverage.sh` |

## Build and install

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build
cmake --install build --prefix /usr/local
```

Use it from CMake:

```cmake
find_package(keytrawl REQUIRED)
target_link_libraries(app PRIVATE keytrawl::keytrawl)
```

Or with pkg-config:

```sh
cc app.c $(pkg-config --cflags --libs keytrawl)
```

Options: `KEYTRAWL_BUILD_TESTS`, `KEYTRAWL_BUILD_EXAMPLES`, `KEYTRAWL_BUILD_FUZZ`,
`KEYTRAWL_BUILD_BENCH` (POSIX), all off by default.

## Single-file form

`scripts/amalgamate.sh` writes `dist/keytrawl/keytrawl.h`. Copy it into your project and, in exactly
one `.c` file:

```c
#define KTW_IMPLEMENTATION
#include "keytrawl/keytrawl.h"
```

Define `KTW_STATIC` as well to keep every function private to that file.

## Versioning

Semantic Versioning. Compatible releases bump the minor version; incompatible ones bump the
major version and the soname. Before 1.0.0 the interface may still change between minor
versions. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
