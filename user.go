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

// user contains data about an Encryptonize user. Note: All fields need to be exported in order for
// gob to serialize them.
type user struct {
	// Salt and password hash for the user's password.
	SaltAndHash []byte

	// A list a groups the user is a member of.
	Groups map[uuid.UUID]struct{}
}

// SealedUser is an encrypted structure which contains data about an Encryptonize user.
type SealedUser struct {
	// The unique ID of the user.
	ID uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

// newUser creates a new user with a random password. All the provided groups are added to the
// user's group list.
func newUser(groups ...uuid.UUID) (user, string, error) {
	pwdHasher := crypto.NewPasswordHasher()
	pwd, saltAndHash, err := pwdHasher.GeneratePassword()
	if err != nil {
		return user{}, "", err
	}

	groupMap := make(map[uuid.UUID]struct{})
	for _, g := range groups {
		groupMap[g] = struct{}{}
	}

	user := user{
		SaltAndHash: saltAndHash,
		Groups:      groupMap,
	}

	return user, pwd, nil
}

// seal encrypts the user.
func (u *user) seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedUser, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(u, id.Bytes())
	if err != nil {
		return SealedUser{}, err
	}
	return SealedUser{id, ciphertext, wrappedKey}, nil
}

// addGroups appends the provided group IDs to the user's group list.
func (u *user) addGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		u.Groups[id] = struct{}{}
	}
}

// removeGroups removes the provided group IDs from the user's group list.
func (u *user) removeGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		delete(u.Groups, id)
	}
}

// containsGroups returns true if all provided group IDs are contained in the user's group list, and
// false otherwise.
func (u *user) containsGroups(ids ...uuid.UUID) bool {
	for _, id := range ids {
		if _, exists := u.Groups[id]; !exists {
			return false
		}
	}
	return true
}

// getGroups returns the set of group IDs contained in the user's group list.
func (u *user) getGroups() map[uuid.UUID]struct{} {
	return u.Groups
}

// unseal decrypts the sealed user.
func (u *SealedUser) unseal(cryptor crypto.CryptorInterface) (user, error) {
	plainUser := user{}
	if err := cryptor.Decrypt(&plainUser, u.ID.Bytes(), u.WrappedKey, u.Ciphertext); err != nil {
		return user{}, err
	}
	return plainUser, nil
}

// verify checks the integrity of the sealed user.
func (u *SealedUser) verify(cryptor crypto.CryptorInterface) bool {
	_, err := u.unseal(cryptor)
	return err == nil
}
