// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
)

var (
	// see https://tools.ietf.org/html/rfc7292#appendix-D
	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
	oidCrlTypeX509Crl          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 23, 1})
	oidKeyBag                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 1})
	oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
	oidCrlBag                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 4})
	oidSecretBag               = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 5})
	oidSafeContentsBag         = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 6})
)

type certBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type crlBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type secretBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey interface{}, err error) {
	pkinfo := new(encryptedPrivateKeyInfo)
	if err = unmarshal(asn1Data, pkinfo); err != nil {
		return nil, errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error())
	}

	pkData, err := pbDecrypt(pkinfo, password)
	if err != nil {
		return nil, errors.New("pkcs12: error decrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	ret := new(asn1.RawValue)
	if err = unmarshal(pkData, ret); err != nil {
		return nil, errors.New("pkcs12: error unmarshaling decrypted private key: " + err.Error())
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(pkData); err != nil {
		return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
	}

	return privateKey, nil
}

func encodePkcs8ShroudedKeyBag(rand io.Reader, privateKey interface{}, password []byte) (asn1Data []byte, err error) {
	var pkData []byte
	if pkData, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
	}

	randomSalt := make([]byte, 8)
	if _, err = rand.Read(randomSalt); err != nil {
		return nil, errors.New("pkcs12: error reading random salt: " + err.Error())
	}
	var paramBytes []byte
	if paramBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
		return nil, errors.New("pkcs12: error encoding params: " + err.Error())
	}

	var pkinfo encryptedPrivateKeyInfo
	pkinfo.AlgorithmIdentifier.Algorithm = oidPBEWithSHAAnd3KeyTripleDESCBC
	pkinfo.AlgorithmIdentifier.Parameters.FullBytes = paramBytes

	if err = pbEncrypt(&pkinfo, pkData, password); err != nil {
		return nil, errors.New("pkcs12: error encrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	if asn1Data, err = asn1.Marshal(pkinfo); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 shrouded key bag: " + err.Error())
	}

	return asn1Data, nil
}

func decodePkcs8KeyBag(asn1Data []byte) (privateKey interface{}, err error) {
	ret := new(asn1.RawValue)
	if err = unmarshal(asn1Data, ret); err != nil {
		return nil, errors.New("pkcs12: error unmarshaling private key: " + err.Error())
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(ret.Bytes); err != nil {
		return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
	}

	return privateKey, nil
}

func encodePkcs8KeyBag(rand io.Reader, privateKey interface{}) (asn1Data []byte, err error) {
	var pkData []byte
	if pkData, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
	}

	return pkData, nil
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
	bag := new(certBag)
	if err := unmarshal(asn1Data, bag); err != nil {
		return nil, errors.New("pkcs12: error decoding cert bag: " + err.Error())
	}
	if !bag.Id.Equal(oidCertTypeX509Certificate) {
		return nil, NotImplementedError("only X509 certificates are supported")
	}
	return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
	var bag certBag
	bag.Id = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding cert bag: " + err.Error())
	}
	return asn1Data, nil
}

func decodeCrlBag(asn1Data []byte) (crlData []byte, err error) {
	bag := new(crlBag)
	if err := unmarshal(asn1Data, bag); err != nil {
		return nil, errors.New("pkcs12: error decoding crl bag: " + err.Error())
	}
	if !bag.Id.Equal(oidCrlTypeX509Crl) {
		return nil, NotImplementedError("only X509 crls are supported")
	}
	return bag.Data, nil
}

func encodeCrlBag(x509Crl *pkix.CertificateList) (asn1Data []byte, err error) {
	var bag certBag
	bag.Id = oidCrlTypeX509Crl

	if bag.Data, err = asn1.Marshal(x509Crl); err != nil {
		return nil, errors.New("pkcs12: error encoding crl: " + err.Error())
	}
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding crl bag: " + err.Error())
	}
	return asn1Data, nil
}

func decodeSecretBag(asn1Data []byte) (secretData []byte, err error) {
	ret := new(asn1.RawValue)
	if err = unmarshal(asn1Data, ret); err != nil {
		return nil, errors.New("pkcs12: error unmarshaling secret data: " + err.Error())
	}

	return ret.FullBytes, nil
}

func encodeSecretBag(secretData []byte) (asn1Data []byte, err error) {
	var bag secretBag
	bag.Id = oidSecretBag

	bag.Data = secretData
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding secret bag: " + err.Error())
	}
	return asn1Data, nil
}
