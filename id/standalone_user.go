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
	"errors"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

// Error returned if a user cannot be authenticated, e.g. if they provide a wrong password.
var ErrNotAuthenticated = errors.New("user not authenticated")

// User contains data about a user. Note: All fields need to be exported in order for gob to
// serialize them.
type User struct {
	// Salt and password hash for the user's password.
	SaltAndHash []byte

	Scopes Scope

	// A list of groups the user is a member of.
	Groups map[uuid.UUID]struct{}
}

// SealedUser is an encrypted structure which contains data about a user.
type SealedUser struct {
	// The unique ID of the user.
	UID uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

var defaultPwdHasher = crypto.NewPasswordHasher()

// newUser creates a new user with a random password and the provided scopes.
func newUser(scopes ...Scope) (User, string, error) {
	pwd, saltAndHash, err := defaultPwdHasher.GeneratePassword()
	if err != nil {
		return User{}, "", err
	}

	user := User{
		SaltAndHash: saltAndHash,
		Scopes:      ScopeUnion(scopes...),
		Groups:      make(map[uuid.UUID]struct{}),
	}

	return user, pwd, nil
}

// authenticate authenticates the calling user with the provided password.
func (u *User) authenticate(password string) error {
	if !defaultPwdHasher.Compare(password, u.SaltAndHash) {
		return ErrNotAuthenticated
	}
	return nil
}

// changePassword authenticates the calling user with the provided password and generates a new
// password for the user. It updates the calling user in place and returns the new password.
func (u *User) changePassword(oldPassword string) (string, error) {
	if err := u.authenticate(oldPassword); err != nil {
		return "", err
	}

	newPwd, newSaltAndHash, err := defaultPwdHasher.GeneratePassword()
	if err != nil {
		return "", err
	}

	u.SaltAndHash = newSaltAndHash

	return newPwd, nil
}

// seal encrypts the user.
func (u *User) seal(uid uuid.UUID, cryptor crypto.CryptorInterface) (SealedUser, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(u, uid.Bytes())
	if err != nil {
		return SealedUser{}, err
	}
	return SealedUser{uid, ciphertext, wrappedKey}, nil
}

// addGroups appends the provided group IDs to the user's group list.
func (u *User) addGroups(gids ...uuid.UUID) {
	for _, gid := range gids {
		u.Groups[gid] = struct{}{}
	}
}

// removeGroups removes the provided group IDs from the user's group list.
func (u *User) removeGroups(gids ...uuid.UUID) {
	for _, gid := range gids {
		delete(u.Groups, gid)
	}
}

// containsGroups returns true if all provided group IDs are contained in the user's group list, and
// false otherwise.
func (u *User) containsGroups(gids ...uuid.UUID) bool {
	for _, gid := range gids {
		if _, exists := u.Groups[gid]; !exists {
			return false
		}
	}
	return true
}

// getGroups returns the set of group IDs contained in the user's group list.
func (u *User) getGroups() map[uuid.UUID]struct{} {
	return u.Groups
}

// unseal decrypts the sealed user.
func (u *SealedUser) unseal(cryptor crypto.CryptorInterface) (User, error) {
	plainUser := User{}
	if err := cryptor.Decrypt(&plainUser, u.UID.Bytes(), u.WrappedKey, u.Ciphertext); err != nil {
		return User{}, err
	}
	return plainUser, nil
}

// verify checks the integrity of the sealed user.
func (u *SealedUser) verify(cryptor crypto.CryptorInterface) bool {
	_, err := u.unseal(cryptor)
	return err == nil
}
