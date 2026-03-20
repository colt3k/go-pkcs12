# Schema Reference

## Top-Level PFX Structure

The package expects a PKCS#12 version 3 PFX PDU:

- `PFX.version` must be `3`
- the outer `authSafe.contentType` must be `data`
- `macData` must be present during decode

If the provided password is the empty string, decode retries MAC verification
with a zero-length byte slice after the standard NULL-terminated BMPString form.

## Supported AuthenticatedSafe Content Types

| Content type | Decode | Encode | Notes |
| --- | --- | --- | --- |
| `data` | yes | yes | Plain safe contents |
| `encryptedData` | yes | yes | Version `0` only |
| anything else | no | no | Returns `NotImplementedError` |

## Supported Safe Bag Types

| Bag type | Decode | Encode | Notes |
| --- | --- | --- | --- |
| `keyBag` | yes | no public writer | Parsed from PKCS#8 |
| `pkcs8ShroudedKeyBag` | yes | yes | Main private-key path |
| `certBag` | yes | yes | X.509 certificates only |
| `crlBag` | yes | helper only | X.509 CRLs only |
| `secretBag` | fork-specific | helper only | Used by `ToPEM` and `example/` |
| `safeContentsBag` | no | no | OID defined, not implemented |

## Attribute Mapping

The following PKCS#12 attributes are surfaced during `ToPEM` as PEM headers:

- `friendlyName`
- `localKeyId`
- `Microsoft CSP Name`

Unknown attributes are preserved as header keys containing the raw OID string,
with values hex-encoded from the ASN.1 payload.

## Supported Algorithms

### Bag Encryption and Decryption

- classic PKCS#12 PBE with SHA-1 and 3-key 3DES-CBC
- classic PKCS#12 PBE with SHA-1 and 40-bit RC2-CBC
- PBES2 with PBKDF2 and AES-256-CBC

PBES2 support accepts PBKDF2 with:

- HMAC-SHA1
- HMAC-SHA256
- omitted PRF, which defaults to SHA-1

Only octet-string PBKDF2 salts are supported.

### MAC Handling

- decode verifies SHA-1 and SHA-256 MACs
- encode emits SHA-1 MACs

## Encode Output Shape

`Encode` always produces:

1. an encrypted safe contents block for certificates
2. an unencrypted safe contents block containing a shrouded private key bag
3. a `localKeyId` attribute derived from the SHA-1 fingerprint of the leaf
   certificate

This mirrors the compatibility layout produced by older OpenSSL tooling.

## Secret-Bag Caveat

The fork's secret-bag decode path is not a generic secret storage framework. It
expects the inner secret payload to be wrapped like a PKCS#8 shrouded blob and
then strips a fixed leading prefix after decryption. Treat that behavior as a
repository-specific interoperability path, not as a complete PKCS#12 secret-bag
implementation.
