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
	"bytes"
	"encoding/gob"
	"errors"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
	"github.com/cybercryptio/d1-lib/data"
	"github.com/cybercryptio/d1-lib/io"
)

var ErrNotFound = errors.New("not found")
var ErrNotAuthorized = errors.New("not authorized")

const (
	DataTypeSealedUser io.DataType = iota + io.DataTypeEnd + 1
	DataTypeSealedGroup
)

// Standalone is an ID Provider that manages its own data.
type Standalone struct {
	userCryptor  crypto.CryptorInterface
	groupCryptor crypto.CryptorInterface
	tokenCryptor crypto.CryptorInterface

	ioProvider io.Provider
}

// NewStandalone creates an ID Provider that uses the provided key material and stores data in the
// given IO provider.
func NewStandalone(uek, gek, tek []byte, ioProvider io.Provider) (Standalone, error) {
	userCryptor, err := crypto.NewAESCryptor(uek)
	if err != nil {
		return Standalone{}, err
	}
	groupCryptor, err := crypto.NewAESCryptor(gek)
	if err != nil {
		return Standalone{}, err
	}
	tokenCryptor, err := crypto.NewAESCryptor(tek)
	if err != nil {
		return Standalone{}, err
	}

	return Standalone{
		userCryptor:  &userCryptor,
		groupCryptor: &groupCryptor,
		tokenCryptor: &tokenCryptor,
		ioProvider:   ioProvider,
	}, nil
}

func (s *Standalone) GetIdentity(token string) (Identity, error) {
	sealedToken, err := data.TokenFromString(token)
	if err != nil {
		return Identity{}, err
	}

	plainToken, err := sealedToken.Unseal(s.tokenCryptor)
	if err != nil {
		return Identity{}, err
	}

	id, err := uuid.FromBytes(plainToken.Plaintext)
	if err != nil {
		return Identity{}, err
	}

	user, err := s.getUser(id)
	if err != nil {
		return Identity{}, err
	}

	groups := make(map[uuid.UUID]AccessGroup, len(user.Groups))
	for gid := range user.getGroups() {
		group, err := s.getGroup(gid)
		if err != nil {
			return Identity{}, err
		}

		groups[gid] = AccessGroup{gid, group.Scopes}
	}

	return Identity{
		ID:     id,
		Scopes: user.Scopes,
		Groups: groups,
	}, nil
}

// NewUser creates a new user with a randomly generated ID and password.
func (s *Standalone) NewUser(scopes ...Scope) (uuid.UUID, string, error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, "", err
	}

	user, password, err := newUser(scopes...)
	if err != nil {
		return uuid.Nil, "", err
	}
	if err := s.putUser(uid, &user, false); err != nil {
		return uuid.Nil, "", err
	}

	return uid, password, nil
}

// LoginUser checks whether the password provided matches the user. If authentication is successful
// a token is generated.
func (s *Standalone) LoginUser(uid uuid.UUID, password string) (string, error) {
	user, err := s.getUser(uid)
	if err != nil {
		return "", ErrNotAuthenticated
	}

	if err := user.authenticate(password); err != nil {
		return "", ErrNotAuthenticated
	}

	token := data.NewToken(uid.Bytes(), data.TokenValidity)
	sealedToken, err := token.Seal(s.tokenCryptor)
	if err != nil {
		return "", ErrNotAuthenticated
	}

	tokenString, err := sealedToken.String()
	if err != nil {
		return "", ErrNotAuthenticated
	}

	return tokenString, nil
}

// ChangeUserPassword authenticates the provided user with the given password and generates a new
// password for the user.
func (s *Standalone) ChangeUserPassword(uid uuid.UUID, oldPassword string) (string, error) {
	user, err := s.getUser(uid)
	if err != nil {
		return "", err
	}

	newPwd, err := user.changePassword(oldPassword)
	if err != nil {
		return "", err
	}
	if err := s.putUser(uid, user, true); err != nil {
		return "", err
	}

	return newPwd, nil
}

// AddUserToGroups adds the user to the provided groups. The authorizing user must be a member of
// all the groups.
func (s *Standalone) AddUserToGroups(token string, uid uuid.UUID, gids ...uuid.UUID) error {
	// Authenticate calling user
	identity, err := s.GetIdentity(token)
	if err != nil {
		return err
	}

	// Check if caller is a member of all groups
	callerGroups := identity.GetIDs()
	for _, gid := range gids {
		if _, ok := callerGroups[gid]; !ok {
			return ErrNotAuthorized
		}
	}

	// Update user
	user, err := s.getUser(uid)
	if err != nil {
		return err
	}

	user.addGroups(gids...)
	if err := s.putUser(uid, user, true); err != nil {
		return err
	}

	return nil
}

// RemoveUserFromGroups removes the user from the provided groups. The authorizing user must be a
// member of all the groups.
func (s *Standalone) RemoveUserFromGroups(token string, uid uuid.UUID, gids ...uuid.UUID) error {
	// Authenticate calling user
	identity, err := s.GetIdentity(token)
	if err != nil {
		return err
	}

	// Check if caller is a member of all groups
	callerGroups := identity.GetIDs()
	for _, gid := range gids {
		if _, ok := callerGroups[gid]; !ok {
			return ErrNotAuthorized
		}
	}

	user, err := s.getUser(uid)
	if err != nil {
		return err
	}

	user.removeGroups(gids...)
	if err := s.putUser(uid, user, true); err != nil {
		return err
	}

	return nil
}

// NewGroup creates a new group and adds the calling user to it.
func (s *Standalone) NewGroup(token string, scopes ...Scope) (uuid.UUID, error) {
	identity, err := s.GetIdentity(token)
	if err != nil {
		return uuid.Nil, err
	}

	gid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	group := newGroup(scopes...)
	if err := s.putGroup(gid, &group); err != nil {
		return uuid.Nil, err
	}

	// Add caller to group
	user, err := s.getUser(identity.ID)
	if err != nil {
		return uuid.Nil, err
	}

	user.addGroups(gid)
	if err := s.putUser(identity.ID, user, true); err != nil {
		return uuid.Nil, err
	}

	return gid, nil
}

// putUser seals the user, encodes the sealed user, and sends it to the IO Provider, either as a
// "Put" or an "Update".
func (s *Standalone) putUser(uid uuid.UUID, user *User, update bool) error {
	sealedUser, err := user.seal(uid, s.userCryptor)
	if err != nil {
		return err
	}

	var userBuffer bytes.Buffer
	enc := gob.NewEncoder(&userBuffer)
	if err := enc.Encode(sealedUser); err != nil {
		return err
	}

	if update {
		return s.ioProvider.Update(sealedUser.UID, DataTypeSealedUser, userBuffer.Bytes())
	}
	return s.ioProvider.Put(sealedUser.UID, DataTypeSealedUser, userBuffer.Bytes())
}

// getUser fetches bytes from the IO Provider, decodes them into a sealed user, and unseals it.
func (s *Standalone) getUser(uid uuid.UUID) (*User, error) {
	userBytes, err := s.ioProvider.Get(uid, DataTypeSealedUser)
	if err != nil {
		return nil, err
	}

	user := &SealedUser{}
	dec := gob.NewDecoder(bytes.NewReader(userBytes))
	err = dec.Decode(user)
	if err != nil {
		return nil, err
	}

	user.UID = uid
	plainUser, err := user.unseal(s.userCryptor)
	if err != nil {
		return nil, err
	}

	return &plainUser, nil
}

// putGroup seals a group, encodes the sealed group, and sends it to the IO Provider.
func (s *Standalone) putGroup(gid uuid.UUID, group *Group) error {
	sealedGroup, err := group.seal(gid, s.groupCryptor)
	if err != nil {
		return err
	}

	var groupBuffer bytes.Buffer
	enc := gob.NewEncoder(&groupBuffer)
	if err := enc.Encode(sealedGroup); err != nil {
		return err
	}

	return s.ioProvider.Put(sealedGroup.GID, DataTypeSealedGroup, groupBuffer.Bytes())
}

// getGroup fetches bytes from the IO Provider, decodes them into a sealed group, and unseals it.
func (s *Standalone) getGroup(gid uuid.UUID) (*Group, error) {
	groupBytes, err := s.ioProvider.Get(gid, DataTypeSealedGroup)
	if err != nil {
		return nil, err
	}

	group := &SealedGroup{}
	dec := gob.NewDecoder(bytes.NewReader(groupBytes))
	err = dec.Decode(group)
	if err != nil {
		return nil, err
	}

	group.GID = gid
	plainGroup, err := group.unseal(s.groupCryptor)
	if err != nil {
		return nil, err
	}

	return &plainGroup, nil
}
