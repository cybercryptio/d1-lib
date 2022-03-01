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

func (a *Access) addGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		a.Groups[id] = struct{}{}
	}
}

func (a *Access) containsGroups(ids ...uuid.UUID) bool {
	for _, id := range ids {
		if _, exists := a.Groups[id]; !exists {
			return false
		}
	}
	return true
}

func (a *Access) removeGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		delete(a.Groups, id)
	}
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
