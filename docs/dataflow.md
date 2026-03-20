# Dataflow

## Decode Path

`DecodeChain` is the main read path:

```text
PFX bytes + password
  -> bmpString(password)
  -> getSafeContents
     -> ASN.1 unmarshal outer PFX
     -> verify MAC over authenticatedSafe bytes
     -> unmarshal authenticatedSafe entries
     -> decrypt encryptedData entries when present
     -> flatten all SafeContents into []safeBag
  -> iterate bags
     -> certBag -> x509.ParseCertificates
     -> pkcs8ShroudedKeyBag -> pbDecrypt -> x509.ParsePKCS8PrivateKey
  -> return private key, leaf cert, CA chain
```

`Decode` is a thin wrapper around `DecodeChain` that rejects additional
certificates.

## Legacy PEM Conversion Flow

`ToPEM` shares the same outer parse and MAC verification path, then maps each
bag into a PEM block:

```text
safeBag
  -> convert attributes to PEM headers
  -> decode payload by bag OID
  -> emit PEM block type
```

Important caveat: RSA and EC private keys are emitted as raw PKCS#1 or EC key
bytes under the generic PEM type `PRIVATE KEY`. That is why the function is
documented as a compatibility helper rather than the preferred decode API.

## Encode Path

`Encode` builds the inverse structure:

```text
private key + leaf cert + CA certs + password
  -> bmpString(password)
  -> SHA-1 fingerprint leaf cert for localKeyId
  -> build cert safe bags
  -> build PKCS#8 shrouded key bag
  -> makeSafeContents(cert bags, password)      // RC2-encrypted
  -> makeSafeContents(key bag, nil)             // outer layer plain, key still shrouded
  -> marshal authenticatedSafe
  -> compute outer SHA-1 MAC
  -> marshal final PFX
```

## Password Handling

- Classic PKCS#12 PBE uses NULL-terminated BMPString/UCS-2 bytes.
- PBES2 handling converts BMPString input back to UTF-8 before calling PBKDF2
  because newer producers commonly expect UTF-8 passwords.
- Empty-string passwords get a compatibility retry during decode.

## Error Boundaries

The main failure points are:

- malformed ASN.1 or trailing data during unmarshal
- MAC mismatch from the wrong password
- unsupported OIDs returned as `NotImplementedError`
- invalid CBC padding returned as `ErrDecryption`
- missing or duplicated key/certificate bags
