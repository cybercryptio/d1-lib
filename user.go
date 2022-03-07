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

type User struct {
	// Note: All fields need to exported in order for gob to serialize them.
	SaltAndHash []byte
	Groups      map[uuid.UUID]struct{}
}

type SealedUser struct {
	ID         uuid.UUID
	Ciphertext []byte
	WrappedKey []byte
}

func newUser(groups ...uuid.UUID) (User, string, error) {
	pwdHasher := crypto.NewPasswordHasher()
	pwd, saltAndHash, err := pwdHasher.GeneratePassword()
	if err != nil {
		return User{}, "", err
	}

	groupMap := make(map[uuid.UUID]struct{})
	for _, g := range groups {
		groupMap[g] = struct{}{}
	}

	user := User{
		SaltAndHash: saltAndHash,
		Groups:      groupMap,
	}

	return user, pwd, nil
}

func (u *User) seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedUser, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(u, id.Bytes())
	if err != nil {
		return SealedUser{}, err
	}
	return SealedUser{id, ciphertext, wrappedKey}, nil
}

func (u *User) addGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		u.Groups[id] = struct{}{}
	}
}

func (u *User) removeGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		delete(u.Groups, id)
	}
}

func (u *User) containsGroups(ids ...uuid.UUID) bool {
	for _, id := range ids {
		if _, exists := u.Groups[id]; !exists {
			return false
		}
	}
	return true
}

func (u *User) getGroups() map[uuid.UUID]struct{} {
	return u.Groups
}

func (u *SealedUser) unseal(cryptor crypto.CryptorInterface) (User, error) {
	user := User{}
	if err := cryptor.Decrypt(&user, u.ID.Bytes(), u.WrappedKey, u.Ciphertext); err != nil {
		return User{}, err
	}
	return user, nil
}

func (u *SealedUser) verify(cryptor crypto.CryptorInterface) bool {
	_, err := u.unseal(cryptor)
	return err == nil
}
