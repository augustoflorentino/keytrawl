# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 1.2.0 - 2026-04-30

Package registry and GitLab tokens, in `KTW_GROUP_CLOUD`.

- npm tokens `npm_` (`KTW_KIND_NPM_TOKEN`, "npm-token"): confirmed by their CRC32, the same scheme
  as GitHub's; a failed checksum reports nothing.
- PyPI tokens `pypi-` (`KTW_KIND_PYPI_TOKEN`, "pypi-token"): the macaroon must start with the
  location `pypi.org` and be at least 85 characters; likely.
- GitLab personal, project and group access tokens `glpat-` (`KTW_KIND_GITLAB_TOKEN`,
  "gitlab-token"): likely with 20 characters; the longer routable form, up to 64 with a ".", is
  an indicator, since GitLab does not publish its layout.

Updating: nothing to change; code that lists the kinds it knows must expect kinds 20 to 22.

Security fixes: none.

## 1.0.0 - 2026-04-22

The caller says what a stream is; the file name no longer decides it.

- `ktw_scanner_reset` takes a fourth argument, `stream`: `KTW_STREAM_AUTO` or `KTW_STREAM_BINARY`.
  In a binary, private keys and key pairs are indicators with `KTW_FLAG_IN_BINARY`. Any other
  value is `KTW_ERR_ARG`.
- A name containing ".so" no longer marks the stream as a binary. The substring also matched
  names such as `server.sol.pem` and `backup.sorted`, demoting real keys to indicators, and a
  caller holding a PE from a UEFI volume, a kernel or a slice of a memory dump had no way to say
  it was a binary. A stream starting with an ELF header is still a binary on its own.
- The command-line scanner takes `-b` to treat every file as a binary.
- Soname `libkeytrawl.so.1`; the ABI is checked against `abi/keytrawl.abi` from here on.

### Upgrading

- Add the fourth argument to every `ktw_scanner_reset` call. `KTW_STREAM_AUTO` keeps the ELF
  header detection; pass `KTW_STREAM_BINARY` where you know the bytes are an executable, a library
  or a firmware blob.
- Code that relied on a `.so` name to demote keys must pass `KTW_STREAM_BINARY` for those files.
  Shared libraries read from the start of the file begin with an ELF header and need nothing.
- Relink: programs built against `libkeytrawl.so.0` do not load `libkeytrawl.so.1`.

Security fixes: none.

## 0.2.0 - 2026-04-17

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
- A scanner holds about 22 KB, was 4 KB; still no allocation while scanning. It remembers the last
  32 keys of a stream for pairing.

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
