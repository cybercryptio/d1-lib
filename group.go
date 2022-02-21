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

type ScopeType uint64 // TODO: This is out of scope (lol)

type Group struct {
	scopes ScopeType
}

type SealedGroup struct {
	ID         uuid.UUID
	ciphertext []byte
	wrappedKey []byte
}

func (g *Group) seal(cryptor crypto.CryptorInterface) (SealedGroup, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return SealedGroup{}, err
	}

	wrappedKey, ciphertext, err := cryptor.EncodeAndEncrypt(g, id.Bytes())
	if err != nil {
		return SealedGroup{}, err
	}

	return SealedGroup{id, ciphertext, wrappedKey}, nil
}

func (g *SealedGroup) unseal(cryptor crypto.CryptorInterface) (Group, error) {
	group := Group{}
	if err := cryptor.DecodeAndDecrypt(&group, g.wrappedKey, g.ciphertext, g.ID.Bytes()); err != nil {
		return Group{}, err
	}
	return group, nil
}

func (g *SealedGroup) verify(cryptor crypto.CryptorInterface) bool {
	_, err := g.unseal(cryptor)
	return err != nil
}
