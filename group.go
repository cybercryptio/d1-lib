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

// group contains data about an Encryptonize group. Note: All fields need to exported in order for
// gob to serialize them.
type group struct {
	Data []byte
}

// SealedGroup is an encrypted structure which contains data about an Encryptonize group.
type SealedGroup struct {
	// The unique ID of the group.
	ID uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

// newGroup creates a new group which contains the provided data.
func newGroup(data []byte) group {
	return group{data}
}

// seal encrypts the group.
func (g *group) seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedGroup, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(g, id.Bytes())
	if err != nil {
		return SealedGroup{}, err
	}

	return SealedGroup{id, ciphertext, wrappedKey}, nil
}

// unseal decrypts the sealed group.
func (g *SealedGroup) unseal(cryptor crypto.CryptorInterface) (group, error) {
	plainGroup := group{}
	if err := cryptor.Decrypt(&plainGroup, g.ID.Bytes(), g.WrappedKey, g.Ciphertext); err != nil {
		return group{}, err
	}
	return plainGroup, nil
}

// verify checks the integrity of the sealed group.
func (g *SealedGroup) verify(cryptor crypto.CryptorInterface) bool {
	_, err := g.unseal(cryptor)
	return err == nil
}
