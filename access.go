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
	groups     map[uuid.UUID]bool
	wrappedOEK []byte
}

type SealedAccess struct {
	ID         uuid.UUID
	ciphertext []byte
	wrappedKey []byte
}

// AccessObject instantiates a new Access Object with given groupID and WOEK.
// A new object starts with Version: 0
func newAccess(groupID uuid.UUID, wrappedOEK []byte) Access {
	return Access{
		groups:     map[uuid.UUID]bool{groupID: true},
		wrappedOEK: wrappedOEK,
	}
}

func (a *Access) seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedAccess, error) {
	wrappedKey, ciphertext, err := cryptor.EncodeAndEncrypt(a, id.Bytes())
	if err != nil {
		return SealedAccess{}, err
	}
	return SealedAccess{id, ciphertext, wrappedKey}, nil
}

// AddGroup adds a new groupID to an Access Object
func (a *Access) addGroup(id uuid.UUID) {
	a.groups[id] = true
}

// ContainsGroup returns whether a groupID is in the Access
func (a *Access) containsGroup(id uuid.UUID) bool {
	return a.groups[id]
}

// RemoveGroup removes a groupID from an Access Object
func (a *Access) removeGroup(id uuid.UUID) {
	delete(a.groups, id)
}

func (a *SealedAccess) unseal(cryptor crypto.CryptorInterface) (Access, error) {
	access := Access{}
	if err := cryptor.DecodeAndDecrypt(&access, a.wrappedKey, a.ciphertext, a.ID.Bytes()); err != nil {
		return Access{}, err
	}
	return access, nil
}

func (a *SealedAccess) verify(cryptor crypto.CryptorInterface) bool {
	_, err := a.unseal(cryptor)
	return err != nil
}
