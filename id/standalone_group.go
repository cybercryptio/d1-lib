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

package id

import (
	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

// Group contains data about a group of users. Note: All fields need to exported in order for
// gob to serialize them.
type Group struct {
	Scopes Scope
}

// SealedGroup is an encrypted structure which contains data about a user group.
type SealedGroup struct {
	// The unique ID of the group.
	GID uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

// NewGroup creates a new group which has the given scopes.
func NewGroup(scopes Scope) Group {
	return Group{scopes}
}

// Seal encrypts the group.
func (g *Group) Seal(gid uuid.UUID, cryptor crypto.CryptorInterface) (SealedGroup, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(g, gid.Bytes())
	if err != nil {
		return SealedGroup{}, err
	}

	return SealedGroup{gid, ciphertext, wrappedKey}, nil
}

// Unseal decrypts the sealed group.
func (g *SealedGroup) Unseal(cryptor crypto.CryptorInterface) (Group, error) {
	plainGroup := Group{}
	if err := cryptor.Decrypt(&plainGroup, g.GID.Bytes(), g.WrappedKey, g.Ciphertext); err != nil {
		return Group{}, err
	}
	return plainGroup, nil
}

// Verify checks the integrity of the sealed group.
func (g *SealedGroup) Verify(cryptor crypto.CryptorInterface) bool {
	_, err := g.Unseal(cryptor)
	return err == nil
}
