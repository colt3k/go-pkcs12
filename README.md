# package pkcs12

[![GoDoc](https://godoc.org/software.sslmate.com/src/go-pkcs12?status.svg)](https://godoc.org/software.sslmate.com/src/go-pkcs12)

Package `pkcs12` implements part of PKCS#12 (also known as P12 or PFX). It is
intended for decoding P12/PFX files for use with Go's `crypto/tls` stack and
for encoding compatibility bundles for older software that still expects
PKCS#12. Since PKCS#12 relies on weak legacy primitives, it should not be the
format you choose for new application designs.

This package is forked from `golang.org/x/crypto/pkcs12`, which is frozen. The
implementation is distilled from [RFC 7292](https://tools.ietf.org/html/rfc7292) and related standards. This fork adds
maintenance updates, secret-bag handling used by the sample program, and
support for newer decrypt paths such as PBES2 with PBKDF2 and AES-256-CBC where
those algorithms appear in incoming data.

This repository holds a supplementary Go cryptography library focused on PKCS#12
interoperability.

## Import Path

The historical upstream import path is:

```go
import "software.sslmate.com/src/go-pkcs12"
```

The active module declared by this repository is:

```go
import "github.com/colt3k/go-pkcs12"
```

Some inherited comments in the source still mention the SSLMate path because
they predate this fork. When consuming this repository directly, follow the
module path from `go.mod`.

## Download/Install

To add the fork to another module:

```bash
go get github.com/colt3k/go-pkcs12
```

For local development in this repository:

```bash
go build -mod=mod ./...
go test -mod=mod ./...
```

Use `-mod=mod` because `vendor/modules.txt` is currently not in sync with
`go.mod`.

## Quick Start

Prefer `DecodeChain` when reading a `.p12`/`.pfx` bundle:

```go
priv, leaf, chain, err := pkcs12.DecodeChain(pfxData, password)
if err != nil {
	return err
}
_ = priv
_ = leaf
_ = chain
```

Use `Encode` when you need to emit a compatibility bundle:

```go
pfxData, err := pkcs12.Encode(rand.Reader, privateKey, leafCert, caCerts, pkcs12.DefaultPassword)
if err != nil {
	return err
}
```

`Decode` is a stricter helper for bundles that contain exactly one certificate
and one private key. `ToPEM` is retained for compatibility and secret-bag
inspection, but it is not the preferred decode API because it emits raw RSA or
EC key bytes under a generic `PRIVATE KEY` PEM label instead of PKCS#8.

## Repository Docs

Additional documentation lives under [`docs/`](docs):

- [`docs/developer-guide.md`](docs/developer-guide.md): repository layout,
  workflows, fixtures, and known development caveats
- [`docs/api-reference.md`](docs/api-reference.md): exported API behavior and
  error model
- [`docs/schema-reference.md`](docs/schema-reference.md): ASN.1 shapes, safe
  bag types, attributes, and supported algorithms
- [`docs/dataflow.md`](docs/dataflow.md): decode and encode execution flow
- [`docs/operator-runbook.md`](docs/operator-runbook.md): troubleshooting and
  day-to-day maintenance procedures
- [`AGENTS.md`](AGENTS.md): concise repository contribution guidelines

## Compatibility Notes

- Decode expects a password-protected PFX version 3 structure with `data` at the
  outer `authSafe` layer.
- Encode writes OpenSSL-style compatibility output: RC2-encrypted certificate
  safe contents, a 3DES-shrouded private key bag, and a SHA-1 MAC.
- Empty-string password handling includes the common compatibility retry from a
  NULL-terminated UCS-2 password to a zero-length byte slice.
- The sample program in `example/main.go` is aimed at secret-bag extraction and
  may need its fixture path adjusted before running locally.

## Report Issues / Send Patches

Open an issue or pull request against this fork. Include:

- the Go version you used
- the exact command you ran
- whether the failure came from `Decode`, `DecodeChain`, `Encode`, or `ToPEM`
- the algorithm or OID if the error is a `NotImplementedError`
- a sanitized sample, fixture, or reproduction snippet when possible

If the behavior appears inherited from SSLMate or `x/crypto/pkcs12`, link the
upstream reference so compatibility tradeoffs are easy to evaluate during review.

Open an issue or PR at https://github.com/SSLMate/go-pkcs12
