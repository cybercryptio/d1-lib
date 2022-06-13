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

package data

import (
	"errors"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

// Error returned if a user cannot be authenticated, e.g. if they provide a wrong password.
var ErrNotAuthenticated = errors.New("user not authenticated")

// User contains data about an Encryptonize user. Note: All fields need to be exported in order for
// gob to serialize them.
type User struct {
	// Salt and password hash for the user's password.
	SaltAndHash []byte

	// A list of groups the user is a member of.
	Groups map[uuid.UUID]struct{}
}

// SealedUser is an encrypted structure which contains data about an Encryptonize user.
type SealedUser struct {
	// The unique ID of the user.
	ID uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

var defaultPwdHasher = crypto.NewPasswordHasher()

// NewUser creates a new user with a random password. All the provided groups are added to the
// user's group list.
func NewUser(groups ...uuid.UUID) (User, string, error) {
	pwd, saltAndHash, err := defaultPwdHasher.GeneratePassword()
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

// Authenticate authenticates the calling user with the provided password.
func (u *User) Authenticate(password string) error {
	if !defaultPwdHasher.Compare(password, u.SaltAndHash) {
		return ErrNotAuthenticated
	}
	return nil
}

// ChangePassword authenticates the calling user with the provided password and generates a new
// password for the user. It updates the calling user in place and returns the new password.
func (u *User) ChangePassword(oldPassword string) (string, error) {
	if err := u.Authenticate(oldPassword); err != nil {
		return "", err
	}

	newPwd, newSaltAndHash, err := defaultPwdHasher.GeneratePassword()
	if err != nil {
		return "", err
	}

	u.SaltAndHash = newSaltAndHash

	return newPwd, nil
}

// Seal encrypts the user.
func (u *User) Seal(id uuid.UUID, cryptor crypto.CryptorInterface) (SealedUser, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(u, id.Bytes())
	if err != nil {
		return SealedUser{}, err
	}
	return SealedUser{id, ciphertext, wrappedKey}, nil
}

// AddGroups appends the provided group IDs to the user's group list.
func (u *User) AddGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		u.Groups[id] = struct{}{}
	}
}

// RemoveGroups removes the provided group IDs from the user's group list.
func (u *User) RemoveGroups(ids ...uuid.UUID) {
	for _, id := range ids {
		delete(u.Groups, id)
	}
}

// ContainsGroups returns true if all provided group IDs are contained in the user's group list, and
// false otherwise.
func (u *User) ContainsGroups(ids ...uuid.UUID) bool {
	for _, id := range ids {
		if _, exists := u.Groups[id]; !exists {
			return false
		}
	}
	return true
}

// GetGroups returns the set of group IDs contained in the user's group list.
func (u *User) GetGroups() map[uuid.UUID]struct{} {
	return u.Groups
}

// Unseal decrypts the sealed user.
func (u *SealedUser) Unseal(cryptor crypto.CryptorInterface) (User, error) {
	plainUser := User{}
	if err := cryptor.Decrypt(&plainUser, u.ID.Bytes(), u.WrappedKey, u.Ciphertext); err != nil {
		return User{}, err
	}
	return plainUser, nil
}

// Verify checks the integrity of the sealed user.
func (u *SealedUser) Verify(cryptor crypto.CryptorInterface) bool {
	_, err := u.Unseal(cryptor)
	return err == nil
}
