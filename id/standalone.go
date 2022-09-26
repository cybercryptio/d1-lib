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
	"context"
	"errors"

	"github.com/gofrs/uuid"
	json "github.com/json-iterator/go"

	"github.com/cybercryptio/d1-lib/v2/crypto"
	"github.com/cybercryptio/d1-lib/v2/data"
	"github.com/cybercryptio/d1-lib/v2/io"
	"github.com/cybercryptio/d1-lib/v2/log"
)

// Error returned if a user was not found.
var ErrUserNotFound = errors.New("user not found")

// Error returned if a group was not found.
var ErrGroupNotFound = errors.New("group not found")

// Error returned if a user already exists.
var ErrUserAlreadyExists = errors.New("user already exists")

// Error returned if a group already exists.
var ErrGroupAlreadyExists = errors.New("group already exists")

// Error returned if the user is not authorized.
var ErrNotAuthorized = errors.New("user not authorized")

const (
	DataTypeSealedUser io.DataType = iota + io.DataTypeEnd + 1
	DataTypeSealedGroup
)

// StandaloneConfig contains the keys with which the Standalone ID Provider will be configured.
type StandaloneConfig struct {
	UEK []byte `koanf:"uek"`
	GEK []byte `koanf:"gek"`
	TEK []byte `koanf:"tek"`
}

// Standalone is an ID Provider that manages its own data.
type Standalone struct {
	userCryptor  crypto.CryptorInterface
	groupCryptor crypto.CryptorInterface
	tokenCryptor crypto.CryptorInterface

	ioProvider io.Provider
}

// NewStandalone creates an ID Provider that uses the provided key material and stores data in the
// given IO provider.
func NewStandalone(config StandaloneConfig, ioProvider io.Provider) (Standalone, error) {
	userCryptor, err := crypto.NewAESCryptor(config.UEK)
	if err != nil {
		return Standalone{}, err
	}
	groupCryptor, err := crypto.NewAESCryptor(config.GEK)
	if err != nil {
		return Standalone{}, err
	}
	tokenCryptor, err := crypto.NewAESCryptor(config.TEK)
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

func (s *Standalone) GetIdentity(ctx context.Context, token string) (Identity, error) {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "get identity")

	sealedToken, err := data.TokenFromString(token)
	if err != nil {
		return Identity{}, ErrNotAuthenticated
	}

	log.Ctx(ctx).Debug().Msg("unsealing token")
	plainToken, err := sealedToken.Unseal(s.tokenCryptor)
	if err != nil {
		return Identity{}, ErrNotAuthenticated
	}

	id := string(plainToken.Plaintext)

	user, err := s.getUser(ctx, id)
	if err != nil {
		return Identity{}, err
	}

	log.Ctx(ctx).Debug().Msgf("fetching %d groups", len(user.Groups))
	groups := make(map[string]AccessGroup, len(user.Groups))
	for gid := range user.getGroups() {
		group, err := s.getGroup(ctx, gid)
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
func (s *Standalone) NewUser(ctx context.Context, scopes ...Scope) (string, string, error) {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "new user")

	uid, err := uuid.NewV4()
	if err != nil {
		return "", "", err
	}
	uidString := uid.String()

	log.Ctx(ctx).Debug().Msg("creating new user")
	user, password, err := newUser(scopes...)
	if err != nil {
		return "", "", err
	}
	if err := s.putUser(ctx, uidString, &user, false); err != nil {
		return "", "", err
	}

	return uidString, password, nil
}

// LoginUser checks whether the password provided matches the user. If authentication is successful
// a token is generated and returned alongside its expiry time in Unix time.
func (s *Standalone) LoginUser(ctx context.Context, uid, password string) (string, int64, error) {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "login user")

	user, err := s.getUser(ctx, uid)
	if err != nil {
		return "", 0, ErrNotAuthenticated
	}

	log.Ctx(ctx).Debug().Msg("authenticating")
	if err := user.authenticate(password); err != nil {
		return "", 0, ErrNotAuthenticated
	}

	log.Ctx(ctx).Debug().Msg("creating token")
	token := data.NewToken([]byte(uid), data.TokenValidity)
	sealedToken, err := token.Seal(s.tokenCryptor)
	if err != nil {
		return "", 0, ErrNotAuthenticated
	}

	tokenString, err := sealedToken.String()
	if err != nil {
		return "", 0, ErrNotAuthenticated
	}

	return tokenString, sealedToken.ExpiryTime.Unix(), nil
}

// ChangeUserPassword authenticates the provided user with the given password and generates a new
// password for the user.
func (s *Standalone) ChangeUserPassword(ctx context.Context, uid, oldPassword string) (string, error) {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "change password")

	user, err := s.getUser(ctx, uid)
	if err != nil {
		return "", ErrNotAuthenticated
	}

	log.Ctx(ctx).Debug().Msg("updating password")
	newPwd, err := user.changePassword(oldPassword)
	if err != nil {
		return "", ErrNotAuthenticated
	}
	if err := s.putUser(ctx, uid, user, true); err != nil {
		return "", err
	}

	return newPwd, nil
}

// AddUserToGroups adds the user to the provided groups. The authorizing user must be a member of
// all the groups.
func (s *Standalone) AddUserToGroups(ctx context.Context, token, uid string, gids ...string) error {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "add user to group")

	// Authenticate calling user
	identity, err := s.GetIdentity(ctx, token)
	if err != nil {
		return err
	}

	// Check if caller is a member of all groups
	log.Ctx(ctx).Debug().Msgf("checking membership of %d groups", len(gids))
	callerGroups := identity.GetIDs()
	for _, gid := range gids {
		if _, ok := callerGroups[gid]; !ok {
			return ErrNotAuthorized
		}
	}

	// Update user
	user, err := s.getUser(ctx, uid)
	if err != nil {
		return err
	}

	log.Ctx(ctx).Debug().Msgf("adding user to %d groups", len(gids))
	user.addGroups(gids...)
	if err := s.putUser(ctx, uid, user, true); err != nil {
		return err
	}

	return nil
}

// RemoveUserFromGroups removes the user from the provided groups. The authorizing user must be a
// member of all the groups.
func (s *Standalone) RemoveUserFromGroups(ctx context.Context, token, uid string, gids ...string) error {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "remove user from group")

	// Authenticate calling user
	identity, err := s.GetIdentity(ctx, token)
	if err != nil {
		return err
	}

	// Check if caller is a member of all groups
	log.Ctx(ctx).Debug().Msgf("checking membership of %d groups", len(gids))
	callerGroups := identity.GetIDs()
	for _, gid := range gids {
		if _, ok := callerGroups[gid]; !ok {
			return ErrNotAuthorized
		}
	}

	user, err := s.getUser(ctx, uid)
	if err != nil {
		return err
	}

	log.Ctx(ctx).Debug().Msgf("removing user from %d groups", len(gids))
	user.removeGroups(gids...)
	if err := s.putUser(ctx, uid, user, true); err != nil {
		return err
	}

	return nil
}

// DeleteUser deletes the user from the IO Provider.
func (s *Standalone) DeleteUser(ctx context.Context, token, uid string) error {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "delete user")

	// Authenticate calling user
	if _, err := s.GetIdentity(ctx, token); err != nil {
		return err
	}

	log.Ctx(ctx).Debug().Msg("deleting user")
	return s.ioProvider.Delete(ctx, []byte(uid), DataTypeSealedUser)
}

// NewGroup creates a new group and adds the calling user to it.
func (s *Standalone) NewGroup(ctx context.Context, token string, scopes ...Scope) (string, error) {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "new group")

	identity, err := s.GetIdentity(ctx, token)
	if err != nil {
		return "", err
	}

	gid, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	gidString := gid.String()

	log.Ctx(ctx).Debug().Msg("creating new group")
	group := newGroup(scopes...)
	if err := s.putGroup(ctx, gidString, &group); err != nil {
		return "", err
	}

	// Add caller to group
	log.Ctx(ctx).Debug().Msg("adding caller to group")
	user, err := s.getUser(ctx, identity.ID)
	if err != nil {
		return "", err
	}

	user.addGroups(gidString)
	if err := s.putUser(ctx, identity.ID, user, true); err != nil {
		return "", err
	}

	return gidString, nil
}

// putUser seals the user, encodes the sealed user, and sends it to the IO Provider, either as a
// "Put" or an "Update".
func (s *Standalone) putUser(ctx context.Context, uid string, user *User, update bool) error {
	log.Ctx(ctx).Debug().Msg("sealing user")
	sealedUser, err := user.seal(uid, s.userCryptor)
	if err != nil {
		return err
	}

	b, err := json.Marshal(sealedUser)
	if err != nil {
		return err
	}

	if update {
		log.Ctx(ctx).Debug().Msg("updating stored user")
		err := s.ioProvider.Update(ctx, []byte(sealedUser.UID), DataTypeSealedUser, b)
		if errors.Is(err, io.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	log.Ctx(ctx).Debug().Msg("storing new user")
	err = s.ioProvider.Put(ctx, []byte(sealedUser.UID), DataTypeSealedUser, b)
	if errors.Is(err, io.ErrAlreadyExists) {
		return ErrUserAlreadyExists
	}
	return err
}

// getUser fetches bytes from the IO Provider, decodes them into a sealed user, and unseals it.
func (s *Standalone) getUser(ctx context.Context, uid string) (*User, error) {
	log.Ctx(ctx).Debug().Msg("getting stored user")
	userBytes, err := s.ioProvider.Get(ctx, []byte(uid), DataTypeSealedUser)
	if errors.Is(err, io.ErrNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	user := &SealedUser{}
	if err = json.Unmarshal(userBytes, user); err != nil {
		return nil, err
	}

	log.Ctx(ctx).Debug().Msg("unsealing user")
	plainUser, err := user.unseal(s.userCryptor)
	if err != nil {
		return nil, err
	}

	return &plainUser, nil
}

// putGroup seals a group, encodes the sealed group, and sends it to the IO Provider.
func (s *Standalone) putGroup(ctx context.Context, gid string, group *Group) error {
	log.Ctx(ctx).Debug().Msg("sealing user")
	sealedGroup, err := group.seal(gid, s.groupCryptor)
	if err != nil {
		return err
	}

	groupBytes, err := json.Marshal(sealedGroup)
	if err != nil {
		return err
	}

	log.Ctx(ctx).Debug().Msg("storing new group")
	err = s.ioProvider.Put(ctx, []byte(sealedGroup.GID), DataTypeSealedGroup, groupBytes)
	if errors.Is(err, io.ErrAlreadyExists) {
		return ErrGroupAlreadyExists
	}
	return err
}

// getGroup fetches bytes from the IO Provider, decodes them into a sealed group, and unseals it.
func (s *Standalone) getGroup(ctx context.Context, gid string) (*Group, error) {
	log.Ctx(ctx).Debug().Msg("getting stored group")
	groupBytes, err := s.ioProvider.Get(ctx, []byte(gid), DataTypeSealedGroup)
	if errors.Is(err, io.ErrNotFound) {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, err
	}

	group := &SealedGroup{}
	if err := json.Unmarshal(groupBytes, group); err != nil {
		return nil, err
	}

	log.Ctx(ctx).Debug().Msg("unsealing group")
	plainGroup, err := group.unseal(s.groupCryptor)
	if err != nil {
		return nil, err
	}

	return &plainGroup, nil
}
