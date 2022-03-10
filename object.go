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

package encryptonize

import (
	"github.com/gofrs/uuid"

	"encryptonize/crypto"
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
	ID uuid.UUID
}

// seal encrypts the object and returns the wrapped encryption key and the sealed object.
func (o *Object) seal(id uuid.UUID, cryptor crypto.CryptorInterface) ([]byte, SealedObject, error) {
	associatedData := make([]byte, 0, uuid.Size+len(o.AssociatedData))
	associatedData = append(associatedData, id.Bytes()...)
	associatedData = append(associatedData, o.AssociatedData...)

	wrappedKey, ciphertext, err := cryptor.Encrypt(o.Plaintext, associatedData)
	if err != nil {
		return nil, SealedObject{}, err
	}

	sealed := SealedObject{
		Ciphertext:     ciphertext,
		AssociatedData: o.AssociatedData,
		ID:             id,
	}

	return wrappedKey, sealed, nil
}

// unseal uses the wrapped key to decrypt the sealed object.
func (o *SealedObject) unseal(wrappedKey []byte, cryptor crypto.CryptorInterface) (Object, error) {
	associatedData := make([]byte, 0, uuid.Size+len(o.AssociatedData))
	associatedData = append(associatedData, o.ID.Bytes()...)
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

// verify uses the wrapped key to check the integrity of the sealed object.
func (o *SealedObject) verify(wrappedKey []byte, cryptor crypto.CryptorInterface) bool {
	_, err := o.unseal(wrappedKey, cryptor)
	return err == nil
}
