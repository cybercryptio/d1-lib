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

type Access struct {
	// Note: All fields need to exported in order for gob to serialize them.
	Groups     map[uuid.UUID]struct{}
	WrappedOEK []byte
}

type SealedAccess struct {
	ID         uuid.UUID
	ciphertext []byte
	wrappedKey []byte
}

// AccessObject instantiates a new Access Object with given groupID and WOEK.
func newAccess(wrappedOEK []byte) Access {
	return Access{
		Groups:     map[uuid.UUID]struct{}{},
		WrappedOEK: wrappedOEK,
	}
}

func (a *Access) seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedAccess, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(a, id.Bytes())
	if err != nil {
		return SealedAccess{}, err
	}
	return SealedAccess{id, ciphertext, wrappedKey}, nil
}

// AddGroup adds a new groupID to an Access Object
func (a *Access) addGroup(id uuid.UUID) {
	a.Groups[id] = struct{}{}
}

// ContainsGroup returns whether a groupID is in the Access
func (a *Access) containsGroup(id uuid.UUID) bool {
	_, exists := a.Groups[id]
	return exists
}

// RemoveGroup removes a groupID from an Access Object
func (a *Access) removeGroup(id uuid.UUID) {
	delete(a.Groups, id)
}

func (a *SealedAccess) unseal(cryptor crypto.CryptorInterface) (Access, error) {
	access := Access{}
	if err := cryptor.Decrypt(&access, a.ID.Bytes(), a.wrappedKey, a.ciphertext); err != nil {
		return Access{}, err
	}
	return access, nil
}

func (a *SealedAccess) verify(cryptor crypto.CryptorInterface) bool {
	_, err := a.unseal(cryptor)
	return err == nil
}
