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

package id

import (
	"github.com/cybercryptio/d1-lib/crypto"
)

// Group contains data about a group of users. Note: All fields need to exported in order for
// gob to serialize them.
type Group struct {
	Scopes Scope
}

// SealedGroup is an encrypted structure which contains data about a user group.
type SealedGroup struct {
	// The group identifier.
	GID string

	Ciphertext []byte
	WrappedKey []byte
}

// newGroup creates a new group which has the given scopes.
func newGroup(scopes ...Scope) Group {
	return Group{Scopes: ScopeUnion(scopes...)}
}

// seal encrypts the group.
func (g *Group) seal(gid string, cryptor crypto.CryptorInterface) (SealedGroup, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(g, gid)
	if err != nil {
		return SealedGroup{}, err
	}

	return SealedGroup{gid, ciphertext, wrappedKey}, nil
}

// unseal decrypts the sealed group.
func (g *SealedGroup) unseal(cryptor crypto.CryptorInterface) (Group, error) {
	plainGroup := Group{}
	if err := cryptor.Decrypt(&plainGroup, g.GID, g.WrappedKey, g.Ciphertext); err != nil {
		return Group{}, err
	}
	return plainGroup, nil
}

// verify checks the integrity of the sealed group.
func (g *SealedGroup) verify(cryptor crypto.CryptorInterface) bool {
	_, err := g.unseal(cryptor)
	return err == nil
}
