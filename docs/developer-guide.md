# Developer Guide

## Repository Layout

Most package logic lives at the module root. `pkcs12.go` owns the top-level PFX
decode and encode flow, `crypto.go` handles bag encryption and decryption,
`mac.go` verifies and emits the outer MAC, `pbkdf.go` implements the PKCS#12
key derivation function, and `safebags.go` parses and builds bag payloads.
Tests sit beside the code as `*_test.go`. The OpenSSL-compatible RC2 block
cipher lives in `internal/rc2/`. `example/main.go` demonstrates secret-bag
extraction.

## Local Workflow

Use Go 1.24.x as declared in `go.mod`. Start with:

```bash
go build -mod=mod ./...
go test -mod=mod ./internal/rc2
go test -mod=mod ./...
```

`-mod=mod` is required at the moment because `vendor/modules.txt` does not match
`go.mod`. If you intentionally update dependencies, plan to refresh vendor data
as a separate change.

## Fixtures and Sample Data

The checked-in PKCS#12 fixture is `./test.p12`. The helper script
`test/create_pkcs12.sh <storepass>` regenerates a sample file with Java
`keytool` and writes it to the repository root. The sample program currently
points at `./test/test.p12`, so update `pkcs12Path` or place a generated copy
there before running:

```bash
go run ./example
```

## What To Change Where

- Adjust outer PFX parsing, bag ordering, or attribute handling in `pkcs12.go`.
- Change supported bag payloads in `safebags.go`.
- Change classic PKCS#12 PBE or PBES2 handling in `crypto.go`.
- Change integrity verification behavior in `mac.go`.
- Change derivation math in `pbkdf.go`.
- Limit RC2-only edits to `internal/rc2/`.

## Known Caveats

- The root package test suite currently has baseline failures on Go 1.24 even
  when run with `-mod=mod`; do not mask those failures in unrelated changes.
- `ToPEM` is intentionally discouraged for general private-key export because it
  does not produce PKCS#8-wrapped PEM blocks.
- This fork carries inherited SSLMate import-path comments alongside a GitHub
  module path in `go.mod`; keep both in mind when editing user-facing docs.

## Documentation Expectations

When you add behavior, update `README.md` plus the relevant files in `docs/`.
Use comments in code for non-obvious interoperability rules, especially around
password encoding, ASN.1 bag shapes, and legacy algorithm constraints.
