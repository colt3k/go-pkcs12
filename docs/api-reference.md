# API Reference

## Public Entry Points

### `const DefaultPassword = "changeit"`

Recommended default for `Encode` when a caller needs a PKCS#12 password but is
already protecting the resulting blob through some stronger external control.

### `func Decode(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, err error)`

Decodes a bundle that contains exactly one end-entity certificate and one
private key. If additional certificates are present, it returns an error.

### `func DecodeChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error)`

Preferred decode API. It returns the first certificate as the leaf certificate
and all subsequent certificates as the CA chain. It requires exactly one
private key bag.

### `func Encode(rand io.Reader, privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error)`

Creates a compatibility-oriented PFX bundle. The emitted structure mirrors the
classic OpenSSL layout:

- certificates live in an RC2-encrypted safe contents block
- the private key lives in a PKCS#8 shrouded bag encrypted with 3DES
- the outer PFX MAC is SHA-1

This is suitable for interoperability, not for designing new crypto storage.

### `func ToPEM(pfxData []byte, password string) ([]*pem.Block, error)`

Legacy compatibility helper. It converts safe bags into PEM blocks and exposes
bag attributes as PEM headers such as `friendlyName` and `localKeyId`.

Use this only when you explicitly need bag-by-bag PEM inspection, including the
fork's secret-bag support. For certificate and private-key loading, prefer
`DecodeChain`.

## Error Model

### `ErrDecryption`

Returned when a bag decrypts but fails padding validation.

### `ErrIncorrectPassword`

Returned when MAC verification fails for the supplied password.

### `type NotImplementedError string`

Returned for unsupported content types, bag types, digest algorithms, KDFs, or
encryption algorithms. These errors usually include the unsupported OID.

## Typical Usage

Decode for TLS setup:

```go
priv, leaf, chain, err := pkcs12.DecodeChain(pfxData, password)
if err != nil {
	return err
}

certs := [][]byte{leaf.Raw}
for _, ca := range chain {
	certs = append(certs, ca.Raw)
}

tlsCert := tls.Certificate{
	PrivateKey:  priv,
	Certificate: certs,
}
_ = tlsCert
```

Encode for compatibility export:

```go
pfxData, err := pkcs12.Encode(rand.Reader, key, leaf, chain, pkcs12.DefaultPassword)
if err != nil {
	return err
}
```

## Internal Package

`internal/rc2` is part of the repository implementation and benchmark surface,
but it is not importable outside the module because it lives under Go's
`internal/` visibility rules.
