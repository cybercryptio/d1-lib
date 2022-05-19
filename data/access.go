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

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
)

// Access is used to manage access to encrypted objects. Note: All member fields need to be exported
// in order for gob to serialize them.
type Access struct {
	// The set of groups that have access to the associated object.
	Groups map[uuid.UUID]struct{}

	// The wrapped encryption key for the associated object.
	WrappedOEK []byte
}

// SealedAccess is an encrypted structure which is used to manage access to encrypted objects.
type SealedAccess struct {
	// The ID of the object this access object provides access to.
	ID uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

// NewAccess creates a new access object which contains the provided wrapped key and no groups.
func NewAccess(wrappedOEK []byte) Access {
	return Access{
		Groups:     map[uuid.UUID]struct{}{},
		WrappedOEK: wrappedOEK,
	}
}

// Seal encrypts the access object.
func (a *Access) Seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedAccess, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(a, id.Bytes())
	if err != nil {
		return SealedAccess{}, err
	}

	sealed := SealedAccess{
		ID:         id,
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
	}

	return sealed, nil
}

// AddGroups appends the provided group IDs to the access object.
func (a *Access) AddGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		a.Groups[id] = struct{}{}
	}
}

// RemoveGroups removes the provided group IDs from the access object.
func (a *Access) RemoveGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		delete(a.Groups, id)
	}
}

// ContainsGroups returns true if all provided group IDs are contained in the access object, and
// false otherwise.
func (a *Access) ContainsGroups(ids ...uuid.UUID) bool {
	for _, id := range ids {
		if _, exists := a.Groups[id]; !exists {
			return false
		}
	}
	return true
}

// GetGroups returns the set of group IDs contained in the access object.
func (a *Access) GetGroups() map[uuid.UUID]struct{} {
	return a.Groups
}

// Unseal decrypts the sealed object.
func (a *SealedAccess) Unseal(cryptor crypto.CryptorInterface) (Access, error) {
	plainAccess := Access{}
	if err := cryptor.Decrypt(&plainAccess, a.ID.Bytes(), a.WrappedKey, a.Ciphertext); err != nil {
		return Access{}, err
	}
	return plainAccess, nil
}
