// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkcs12 extracts secret-bag payloads from PKCS#12 (P12/PFX) data.
package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"

	"github.com/pkg/errors"
)

var (
	oidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidEncryptedDataContentType = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})

	oidFriendlyName     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
	oidLocalKeyID       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 21})
	oidMicrosoftCSPName = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 17, 1})
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.AlgorithmIdentifier
}

func (i encryptedPrivateKeyInfo) Data() []byte {
	return i.EncryptedData
}

const secretBagType = "SECRET BAG"

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out interface{}) error {
	trailing, err := asn1.Unmarshal(in, out)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(trailing) != 0 {
		return errors.WithStack(errors.New("pkcs12: trailing data found"))
	}
	return nil
}

// ToPEM extracts secret bags from pfxData and returns them as PEM blocks.
// Non-secret safe bags are ignored.
func ToPEM(pfxData []byte, password string) ([]*pem.Block, error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, errors.WithStack(ErrIncorrectPassword)
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)
	if err != nil {
		return nil, err
	}

	blocks := make([]*pem.Block, 0, len(bags))
	for i := range bags {
		if !bags[i].Id.Equal(oidSecretBag) {
			continue
		}

		block, err := convertBag(&bags[i], encodedPassword)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}

	if len(blocks) == 0 {
		return nil, errors.WithStack(NotImplementedError("only secret bags are supported"))
	}

	return blocks, nil
}

// convertBag maps one PKCS#12 secret bag into a PEM block and carries selected
// PKCS#12 attributes into PEM headers.
func convertBag(bag *safeBag, password []byte) (*pem.Block, error) {
	block := &pem.Block{
		Type:    secretBagType,
		Headers: make(map[string]string),
	}

	for _, attribute := range bag.Attributes {
		k, v, err := convertAttribute(&attribute)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		block.Headers[k] = v
	}

	secretData, err := decodeSecretBag(bag.Value.Bytes, password)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	block.Bytes = secretData

	return block, nil
}

// convertAttribute normalizes supported PKCS#12 attribute OIDs into OpenSSL-
// style PEM header keys.
func convertAttribute(attribute *pkcs12Attribute) (key, value string, err error) {
	isString := false

	switch {
	case attribute.Id.Equal(oidFriendlyName):
		key = "friendlyName"
		isString = true
	case attribute.Id.Equal(oidLocalKeyID):
		key = "localKeyId"
	case attribute.Id.Equal(oidMicrosoftCSPName):
		// This key is chosen to match OpenSSL.
		key = "Microsoft CSP Name"
		isString = true
	default:
		key = attribute.Id.String()
		value = hex.EncodeToString(attribute.Value.Bytes)
		return key, value, nil
	}

	if isString {
		if err := unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
			return "", "", errors.WithStack(err)
		}
		if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
			return "", "", errors.WithStack(err)
		}
	} else {
		var id []byte
		if err := unmarshal(attribute.Value.Bytes, &id); err != nil {
			return "", "", errors.WithStack(err)
		}
		value = hex.EncodeToString(id)
	}

	return key, value, nil
}

// getSafeContents parses the outer PFX, verifies the MAC, and flattens every
// authenticated safe entry into a single safeBag slice for ToPEM.
func getSafeContents(p12Data, password []byte) (bags []safeBag, updatedPassword []byte, err error) {
	pfx := new(pfxPdu)
	if err := unmarshal(p12Data, pfx); err != nil {
		return nil, nil, errors.WithStack(errors.New("pkcs12: error reading P12 data: " + err.Error()))
	}

	if pfx.Version != 3 {
		return nil, nil, errors.WithStack(NotImplementedError("can only decode v3 PFX PDU's"))
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, nil, errors.WithStack(NotImplementedError("only password-protected PFX is implemented"))
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, errors.WithStack(err)
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, nil, errors.WithStack(errors.New("pkcs12: no MAC in data"))
	}

	if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
			// Some implementations use an empty byte array for the empty-string password.
			password = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password)
		}
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, errors.WithStack(err)
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, nil, errors.WithStack(err)
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, nil, err
			}
			if encryptedData.Version != 0 {
				return nil, nil, errors.WithStack(NotImplementedError("only version 0 of EncryptedData is supported"))
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
				return nil, nil, errors.WithStack(err)
			}
		default:
			return nil, nil, errors.WithStack(NotImplementedError("only data and encryptedData content types are supported in authenticated safe"))
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			return nil, nil, errors.WithStack(err)
		}
		bags = append(bags, safeContents...)
	}

	return bags, password, nil
}
