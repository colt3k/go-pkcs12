# Operator Runbook

## Purpose

This runbook is for maintainers or integrators who need to build the library,
reproduce PKCS#12 parsing issues, regenerate local fixtures, or triage incoming
bundle failures.

## Prerequisites

- Go 1.24.x
- `keytool` if you want to regenerate the sample `.p12`
- a local checkout of this repository

## Standard Commands

Build and test with module resolution instead of vendor mode:

```bash
go build -mod=mod ./...
go test -mod=mod ./internal/rc2
go test -mod=mod ./...
```

If you see an inconsistent vendoring error, that is the current baseline. Use
`-mod=mod` for day-to-day work until vendor metadata is refreshed intentionally.

## Regenerate the Sample Keystore

```bash
bash test/create_pkcs12.sh myvault
```

This writes `./test.p12` at the repository root. The script warns if Java is
newer than 17 because newer `keytool` behavior can change PKCS#12 outputs.

## Run the Example

`example/main.go` extracts a `SECRET BAG` value by matching `friendlyName`.
Before running it, confirm that `pkcs12Path` points at a real file; the checked
in fixture is `./test.p12`, while the sample defaults to `./test/test.p12`.

```bash
go run ./example
```

## Triage Decode Failures

1. Confirm whether the caller should be using `DecodeChain` instead of `ToPEM`.
2. Record the exact error:
   - `ErrIncorrectPassword`: wrong password or mismatched MAC
   - `ErrDecryption`: decrypted bytes failed padding validation
   - `NotImplementedError`: unsupported OID or structure
3. Capture the producer if known: OpenSSL, Java `keytool`, Windows, HSM export,
   or another tool.
4. Check whether the input uses:
   - PFX version other than 3
   - outer content types other than `data`
   - bag types other than cert, key, or shrouded key
   - PBES2 parameters other than PBKDF2 + AES-256-CBC

## Triage Encode Complaints

- Remember that `Encode` intentionally emits legacy-compatible algorithms:
  RC2 for certificate safe contents, 3DES for the shrouded key, and SHA-1 MAC.
- If a consumer expects PKCS#8 PEM output, do not route through `ToPEM`.
- If interop changed after a dependency update, compare the resulting PFX with
  the previous output before changing algorithms.

## Known Repository Baselines

- Root-package tests currently fail on Go 1.24 even when `-mod=mod` is used.
- `internal/rc2` tests are the cleanest targeted verification point for cipher
  changes.
- The secret-bag path is fork-specific and should be validated with real sample
  inputs before relying on it operationally.
