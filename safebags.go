// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"encoding/asn1"

	"github.com/pkg/errors"
)

var (
	oidPKCS8ShroundedKeyBag = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidSecretBag            = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 5})
)

const secretBagPayloadOffset = 22

type secretBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

// decodeSecretBag implements the fork-specific secret-bag path used by ToPEM.
// It expects the inner payload to be carried as a shrouded PKCS#8 blob and
// returns the decrypted bytes after trimming the fixed wrapper prefix used by
// those inputs.
func decodeSecretBag(asn1Data, password []byte) (secretData []byte, err error) {
	bag := new(secretBag)
	if err := unmarshal(asn1Data, bag); err != nil {
		return nil, errors.WithStack(errors.New("pkcs12: error decoding secret bag: " + err.Error()))
	}
	if !bag.Id.Equal(oidPKCS8ShroundedKeyBag) {
		return nil, errors.WithStack(NotImplementedError("only secret bags are supported"))
	}

	pkinfo := new(encryptedPrivateKeyInfo)
	if err = unmarshal(bag.Data, pkinfo); err != nil {
		return nil, errors.WithStack(errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error()))
	}

	pkData, err := pbDecrypt(pkinfo, password)
	if err != nil {
		return nil, errors.WithStack(errors.New("pkcs12: error decrypting PKCS#8 shrouded key bag: " + err.Error()))
	}
	if len(pkData) < secretBagPayloadOffset {
		return nil, errors.WithStack(errors.New("pkcs12: secret bag payload too short"))
	}

	return pkData[secretBagPayloadOffset:], nil
}
