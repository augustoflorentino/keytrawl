# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.1.0 - unreleased

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
