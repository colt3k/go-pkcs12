# package pkcs12

This repository is a deliberately narrowed fork of `go-pkcs12`. It only keeps
the code needed to support `pkcs12.ToPEM` for secret-bag extraction.

`ToPEM` now:

- returns `SECRET BAG` PEM blocks only
- ignores non-secret safe bags in the input PFX
- keeps PKCS#12 MAC verification and decrypt support needed to reach those bags

## Import Path

```go
import "github.com/colt3k/go-pkcs12"
```

## Supported Input

- PFX version 3
- password-protected outer `authSafe`
- inner `data` and `encryptedData` content types
- the fork-specific secret-bag format already handled by this repository
- classic PKCS#12 PBE and PBES2/PBKDF2/AES-256-CBC where encountered during decryption

Anything outside that scope is intentionally unsupported in this minimized
fork.

## Usage

```go
blocks, err := pkcs12.ToPEM(pfxData, password)
if err != nil {
	return err
}

for _, block := range blocks {
	if block.Type != "SECRET BAG" {
		continue
	}
	secret := string(block.Bytes)
	_ = secret
}
```

## Development

```bash
go build -mod=mod ./...
go test -mod=mod ./...
```
