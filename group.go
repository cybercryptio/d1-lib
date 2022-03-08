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

type group struct {
	// Note: All fields need to exported in order for gob to serialize them.
	Data []byte
}

type SealedGroup struct {
	ID         uuid.UUID
	Ciphertext []byte
	WrappedKey []byte
}

func newGroup(data []byte) group {
	return group{data}
}

func (g *group) seal(cryptor crypto.CryptorInterface) (SealedGroup, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return SealedGroup{}, err
	}

	wrappedKey, ciphertext, err := cryptor.Encrypt(g, id.Bytes())
	if err != nil {
		return SealedGroup{}, err
	}

	return SealedGroup{id, ciphertext, wrappedKey}, nil
}

func (g *SealedGroup) unseal(cryptor crypto.CryptorInterface) (group, error) {
	plainGroup := group{}
	if err := cryptor.Decrypt(&plainGroup, g.ID.Bytes(), g.WrappedKey, g.Ciphertext); err != nil {
		return group{}, err
	}
	return plainGroup, nil
}

func (g *SealedGroup) verify(cryptor crypto.CryptorInterface) bool {
	_, err := g.unseal(cryptor)
	return err == nil
}
