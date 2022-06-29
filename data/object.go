// Copyright (C) 2022 CYBERCRYPT
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package data

import (
	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

// Object contains plaintext data provided to D1 for encryption.
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
