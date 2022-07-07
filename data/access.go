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

// Access is used to manage access to encrypted objects. Note: All member fields need to be exported
// in order for gob to serialize them.
type Access struct {
	// The set of groups that have access to the associated object. The format of the key strings
	// depends on how the ID Provider implements group identifiers.
	Groups map[string]struct{}

	// The wrapped encryption key for the associated object.
	WrappedOEK []byte
}

// SealedAccess is an encrypted structure which is used to manage access to encrypted objects.
type SealedAccess struct {
	// The ID of the object this access object provides access to.
	OID uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

// NewAccess creates a new access object which contains the provided wrapped key and no groups.
func NewAccess(wrappedOEK []byte) Access {
	return Access{
		Groups:     map[string]struct{}{},
		WrappedOEK: wrappedOEK,
	}
}

// Seal encrypts the access object.
func (a *Access) Seal(oid uuid.UUID, cryptor crypto.CryptorInterface) (SealedAccess, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(a, oid.Bytes())
	if err != nil {
		return SealedAccess{}, err
	}

	sealed := SealedAccess{
		OID:        oid,
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
	}

	return sealed, nil
}

// AddGroups appends the provided group IDs to the access object.
func (a *Access) AddGroups(ids ...string) {
	for _, id := range ids {
		a.Groups[id] = struct{}{}
	}
}

// RemoveGroups removes the provided group IDs from the access object.
func (a *Access) RemoveGroups(ids ...string) {
	for _, id := range ids {
		delete(a.Groups, id)
	}
}

// ContainsGroups returns true if all provided group IDs are contained in the access object, and
// false otherwise.
func (a *Access) ContainsGroups(ids ...string) bool {
	for _, id := range ids {
		if _, exists := a.Groups[id]; !exists {
			return false
		}
	}
	return true
}

// GetGroups returns the set of group IDs contained in the access object.
func (a *Access) GetGroups() map[string]struct{} {
	return a.Groups
}

// Unseal decrypts the sealed object.
func (a *SealedAccess) Unseal(cryptor crypto.CryptorInterface) (Access, error) {
	plainAccess := Access{}
	if err := cryptor.Decrypt(&plainAccess, a.OID.Bytes(), a.WrappedKey, a.Ciphertext); err != nil {
		return Access{}, err
	}
	return plainAccess, nil
}
