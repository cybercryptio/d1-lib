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

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
)

// access is used to manage access to encrypted objects. Note: All member fields need to be exported
// in order for gob to serialize them.
type access struct {
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

// newAccess creates a new access object which contains the provided wrapped key and no groups.
func newAccess(wrappedOEK []byte) access {
	return access{
		Groups:     map[uuid.UUID]struct{}{},
		WrappedOEK: wrappedOEK,
	}
}

// seal encrypts the access object.
func (a *access) seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedAccess, error) {
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

// addGroups appends the provided group IDs to the access object.
func (a *access) addGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		a.Groups[id] = struct{}{}
	}
}

// addGroups removes the provided group IDs from the access object.
func (a *access) removeGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		delete(a.Groups, id)
	}
}

// containsGroups returns true if all provided group IDs are contained in the access object, and
// false otherwise.
func (a *access) containsGroups(ids ...uuid.UUID) bool {
	for _, id := range ids {
		if _, exists := a.Groups[id]; !exists {
			return false
		}
	}
	return true
}

// getGroups returns the set of group IDs contained in the access object.
func (a *access) getGroups() map[uuid.UUID]struct{} {
	return a.Groups
}

// unseal decrypts the sealed object.
func (a *SealedAccess) unseal(cryptor crypto.CryptorInterface) (access, error) {
	plainAccess := access{}
	if err := cryptor.Decrypt(&plainAccess, a.ID.Bytes(), a.WrappedKey, a.Ciphertext); err != nil {
		return access{}, err
	}
	return plainAccess, nil
}

// verify checks the integrity of the sealed object.
func (a *SealedAccess) verify(cryptor crypto.CryptorInterface) bool {
	_, err := a.unseal(cryptor)
	return err == nil
}
