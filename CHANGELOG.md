# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.2.0 - unreleased

Key pairs (K10): a public key whose private key is in the same stream, the sign of a factory key
shared by every unit.

- New kind `KTW_KIND_KEY_PAIR` ("key-pair"), group `KTW_GROUP_PAIRS` (now in `KTW_GROUP_ALL`),
  check `KTW_CHECK_KEY_MATCH` and `ktw_finding_pair_offset`. The finding points at the public key;
  the pair offset at the private one.
- Public keys read: PEM `PUBLIC KEY`, `RSA PUBLIC KEY` and `CERTIFICATE`, DER
  SubjectPublicKeyInfo anywhere (certificates included) and OpenSSH public key lines.
- The match is by the public value itself (RSA n, DSA y, EC point, Ed25519 key). PKCS#8 keys
  without one have it computed: Ed25519 from the seed, DSA as g^x mod p. Encrypted PKCS#8 and
  legacy encrypted PEM keys cannot be matched; encrypted OpenSSH keys can, their public key is in
  clear.
- PKCS#8 DSA keys now have their parameters checked as p, q, g.
- A scanner holds about 18 KB, was 4 KB; still no allocation while scanning.

Updating: code that passes `KTW_GROUP_ALL` gets the new findings once rebuilt; code that lists the
kinds it knows must expect kind 19.

Security fixes: none.

## 0.1.0 - 2026-04-08

First release.

- One-pass streaming scan of raw bytes: input in pieces of any size, findings independent of how
  it is cut, constant memory (about 4 KB per scanner), no allocation while scanning.
- One compiled catalog shared read-only by any number of scanners and threads.
- PEM private keys (RSA, EC, DSA, OpenSSH, PKCS#8, encrypted PKCS#8) with the ASN.1 or OpenSSH
  structure checked; bare DER private keys (PKCS#1, DSA, SEC 1, PKCS#8, PKCS#8 with PBES2).
- AWS, Google, GitHub (CRC32 checksum), Slack and Stripe tokens.
- Wi-Fi passphrases and authorized_keys lines, enabled by the stream name.
- User literals with an optional validator callback.
- Masked evidence: at most the first and last 4 bytes of a secret.
- `keytrawl` command-line scanner in `examples/`.

Updating: nothing to update from.

Security fixes: none.
