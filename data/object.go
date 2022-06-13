// Copyright 2020-2022 CYBERCRYPT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package data

import (
	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

// Object contains plaintext data provided to Encryptonize for encryption.
type Object struct {
	// Sensitive plaintext data that will be encrypted.
	Plaintext []byte

	// Associated data that will not be encrypted but will be authenticated.
	AssociatedData []byte
}

// SealedObject contains encrypted and authenticated data.
type SealedObject struct {
	// The encrypted contents of the object.
	Ciphertext []byte

	// Associated data in plaintext. This data is authenticated upon decryption, and can be used as
	// metadata about the ciphertext.
	AssociatedData []byte

	// A unique ID which identifies the object. The ID is authenticated upon decryption.
	OID uuid.UUID
}

// Seal encrypts the object and returns the wrapped encryption key and the sealed object.
func (o *Object) Seal(oid uuid.UUID, cryptor crypto.CryptorInterface) ([]byte, SealedObject, error) {
	associatedData := make([]byte, 0, uuid.Size+len(o.AssociatedData))
	associatedData = append(associatedData, oid.Bytes()...)
	associatedData = append(associatedData, o.AssociatedData...)

	wrappedKey, ciphertext, err := cryptor.Encrypt(o.Plaintext, associatedData)
	if err != nil {
		return nil, SealedObject{}, err
	}

	sealed := SealedObject{
		Ciphertext:     ciphertext,
		AssociatedData: o.AssociatedData,
		OID:            oid,
	}

	return wrappedKey, sealed, nil
}

// Unseal uses the wrapped key to decrypt the sealed object.
func (o *SealedObject) Unseal(wrappedKey []byte, cryptor crypto.CryptorInterface) (Object, error) {
	associatedData := make([]byte, 0, uuid.Size+len(o.AssociatedData))
	associatedData = append(associatedData, o.OID.Bytes()...)
	associatedData = append(associatedData, o.AssociatedData...)

	plaintext := []byte{}
	err := cryptor.Decrypt(&plaintext, associatedData, wrappedKey, o.Ciphertext)
	if err != nil {
		return Object{}, err
	}

	return Object{
		Plaintext:      plaintext,
		AssociatedData: o.AssociatedData,
	}, nil
}
