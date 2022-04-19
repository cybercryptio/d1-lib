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

/*
Encryptonize is a library that provides easy access to data encryption with built in access control.
*/
package encryptonize

import (
	"errors"

	"github.com/gofrs/uuid"

	"encryptonize/crypto"
)

// Error returned if a user cannot be authenticated, e.g. if they provide a wrong password.
var ErrNotAuthenticated = errors.New("user not authenticated")

// Error returned if a user tries to access data they are not authorized for.
var ErrNotAuthorized = errors.New("user not authorized")

// Keys contains the master key material used by Encryptonize. All keys must be 32 bytes.
type Keys struct {
	// Key Encryption Key used for wrapping randomly generated encryption keys.
	KEK []byte `koanf:"kek"`

	// Access Encryption Key used for encrypting access objects.
	AEK []byte `koanf:"aek"`

	// Token Encryption Key used for encrypting tokens.
	TEK []byte `koanf:"tek"`

	// User Encryption Key used for encrypting user data.
	UEK []byte `koanf:"uek"`

	// Group Encryption Key used for encrypting group data.
	GEK []byte `koanf:"gek"`
}

// Encryptonize is the entry point to the library. All main functionality is exposed through methods
// on this struct.
type Encryptonize struct {
	ObjectCryptor, AccessCryptor, TokenCryptor, UserCryptor, GroupCryptor crypto.CryptorInterface
}

// New creates a new instance of Encryptonize which uses the given configuration.
func New(keys Keys) (Encryptonize, error) {
	objectCryptor, err := crypto.NewAESCryptor(keys.KEK)
	if err != nil {
		return Encryptonize{}, err
	}
	accessCryptor, err := crypto.NewAESCryptor(keys.AEK)
	if err != nil {
		return Encryptonize{}, err
	}
	tokenCryptor, err := crypto.NewAESCryptor(keys.TEK)
	if err != nil {
		return Encryptonize{}, err
	}
	userCryptor, err := crypto.NewAESCryptor(keys.UEK)
	if err != nil {
		return Encryptonize{}, err
	}
	groupCryptor, err := crypto.NewAESCryptor(keys.GEK)
	if err != nil {
		return Encryptonize{}, err
	}

	return Encryptonize{&objectCryptor, &accessCryptor, &tokenCryptor, &userCryptor, &groupCryptor}, nil
}

////////////////////////////////////////////////////////
//                       Object                       //
////////////////////////////////////////////////////////

// Encrypt creates a new sealed object containing the provided plaintext data as well as an access
// object that controls access to that data. The calling user is automatically added to the access
// object. To grant other users access, see AddGroupsToAccess and AddUserToGroups.
//
// The sealed object and the sealed access object are not sensitive data.
func (e *Encryptonize) Encrypt(user *SealedUser, object *Object) (SealedObject, SealedAccess, error) {
	if !user.verify(e.UserCryptor) {
		return SealedObject{}, SealedAccess{}, ErrNotAuthorized
	}

	id, err := uuid.NewV4()
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}

	wrappedOEK, sealedObject, err := object.seal(id, e.ObjectCryptor)
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}

	access := newAccess(wrappedOEK)
	access.addGroups(user.ID)
	sealedAccess, err := access.seal(sealedObject.ID, e.AccessCryptor)
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}

	return sealedObject, sealedAccess, nil
}

// Update creates a new sealed object containing the provided plaintext data but uses a previously
// created access object to control access to that data. The authorizing user must be part of the
// provided access object, either directly or through group membership. The access object is
// modified in-place, and any object previously associated with this access object can no longer be
// decrypted.
//
// The sealed object is not sensitive data.
func (e *Encryptonize) Update(authorizer *SealedUser, object *Object, access *SealedAccess) (SealedObject, error) {
	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return SealedObject{}, err
	}

	wrappedOEK, sealedObject, err := object.seal(access.ID, e.ObjectCryptor)
	if err != nil {
		return SealedObject{}, err
	}

	plainAccess.WrappedOEK = wrappedOEK
	sealedAccess, err := plainAccess.seal(sealedObject.ID, e.AccessCryptor)
	if err != nil {
		return SealedObject{}, err
	}
	*access = sealedAccess

	return sealedObject, nil
}

// Decrypt extracts the plaintext from a sealed object. The authorizing user must be part of the
// provided access object, either directly or through group membership.
//
// The unsealed object may contain sensitive data.
func (e *Encryptonize) Decrypt(authorizer *SealedUser, object *SealedObject, access *SealedAccess) (Object, error) {
	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return Object{}, err
	}

	return object.unseal(plainAccess.WrappedOEK, e.ObjectCryptor)
}

////////////////////////////////////////////////////////
//                       Token                        //
////////////////////////////////////////////////////////

// CreateToken encapsulates the provided plaintext data in an opaque, self contained token with an
// expiry time given by TokenValidity.
func (e *Encryptonize) CreateToken(plaintext []byte) (SealedToken, error) {
	token := newToken(plaintext, TokenValidity)
	return token.seal(e.TokenCryptor)
}

// GetTokenContents extracts the plaintext data from a sealed token, provided that the token has not
// expired.
func (e *Encryptonize) GetTokenContents(token *SealedToken) ([]byte, error) {
	plainToken, err := token.unseal(e.TokenCryptor)
	if err != nil {
		return nil, err
	}
	return plainToken.Plaintext, nil
}

////////////////////////////////////////////////////////
//                       Access                       //
////////////////////////////////////////////////////////

// GetAccessGroups extracts the set of group IDs contained in the provided access object. The
// authorizing user must be part of the access object.
//
// The set of group IDs is somewhat sensitive data, as it reveals what groups/users have access to
// the associated object.
func (e *Encryptonize) GetAccessGroups(authorizer *SealedUser, access *SealedAccess) (map[uuid.UUID]struct{}, error) {
	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return nil, err
	}
	return plainAccess.getGroups(), nil
}

// AddGroupsToAccess appends the provided groups to the provided access object, giving them access
// to the associated object. The authorizing user must be part of the access object. The access
// object is modified in-place.
func (e *Encryptonize) AddGroupsToAccess(authorizer *SealedUser, access *SealedAccess, groups ...*SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.addGroups(groupIDs...)

	*access, err = plainAccess.seal(access.ID, e.AccessCryptor)
	return err
}

// RemoveGroupsFromAccess removes the provided groups from the provided access object, preventing
// them from accessing the associated object. The authorizing user must be part of the access
// object. The access object is modified in-place.
func (e *Encryptonize) RemoveGroupsFromAccess(authorizer *SealedUser, access *SealedAccess, groups ...*SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.removeGroups(groupIDs...)

	*access, err = plainAccess.seal(access.ID, e.AccessCryptor)
	return err
}

// AuthorizeUser checks whether the provided user is part of the provided access object, i.e.
// whether they are authorized to access the associated object. An error is returned if the user is
// not authorized.
func (e *Encryptonize) AuthorizeUser(user *SealedUser, access *SealedAccess) error {
	_, err := e.authorizeAccess(user, access)
	return err
}

////////////////////////////////////////////////////////
//                        User                        //
////////////////////////////////////////////////////////

// NewUser creates a new Encryptonize user as well as an initial group for that user. The newly
// created user and group has the same ID. The user's own group contains the provided data, and the
// user is added to any additional groups provided. A randomly generated password is also created
// and returned to the caller.
//
// The sealed user and group are not sensitive data. The generated password is sensitive data.
func (e *Encryptonize) NewUser(data []byte, groups ...*SealedGroup) (SealedUser, SealedGroup, string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return SealedUser{}, SealedGroup{}, "", err
	}

	return e.NewUserWithID(id, data, groups...)
}

func (e *Encryptonize) NewUserWithID(id uuid.UUID, data []byte, groups ...*SealedGroup) (SealedUser, SealedGroup, string, error) {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return SealedUser{}, SealedGroup{}, "", err
	}

	group := newGroup(data)
	sealedGroup, err := (&group).seal(id, e.GroupCryptor)
	if err != nil {
		return SealedUser{}, SealedGroup{}, "", err
	}

	user, pwd, err := newUser(append(groupIDs, id)...)
	if err != nil {
		return SealedUser{}, SealedGroup{}, "", err
	}

	sealedUser, err := user.seal(id, e.UserCryptor)
	if err != nil {
		return SealedUser{}, SealedGroup{}, "", err
	}

	return sealedUser, sealedGroup, pwd, nil
}

// GetUserGroups extracts user's set of group IDs.
//
// The set of group IDs is somewhat sensitive data, as it reveals what groups the user is a member
// of.
func (e *Encryptonize) GetUserGroups(user *SealedUser) (map[uuid.UUID]struct{}, error) {
	plainUser, err := user.unseal(e.UserCryptor)
	if err != nil {
		return nil, err
	}
	return plainUser.getGroups(), nil
}

// AuthenticateUser checks whether the password provided matches the user. If not, an error is
// returned.
func (e *Encryptonize) AuthenticateUser(user *SealedUser, password string) error {
	plainUser, err := user.unseal(e.UserCryptor)
	if err != nil {
		return err
	}
	if err := plainUser.authenticate(password); err != nil {
		return err
	}
	return nil
}

// ChangeUserPassword authenticates the provided sealed user with the given password and generates a new password for the user.
// It modifies the user object in place and returns the generated password.
//
// Any copies of the old sealed user must be disposed of.
func (e *Encryptonize) ChangeUserPassword(user *SealedUser, oldPassword string) (string, error) {
	plainUser, err := user.unseal(e.UserCryptor)
	if err != nil {
		return "", err
	}

	newPwd, err := plainUser.changePassword(oldPassword)
	if err != nil {
		return "", err
	}

	*user, err = plainUser.seal(user.ID, e.UserCryptor)
	if err != nil {
		return "", err
	}

	return newPwd, nil
}

// AddUserToGroups adds the user to the provided groups. The authorizing user must be a member of
// all the groups. The user is modified in-place.
func (e *Encryptonize) AddUserToGroups(authorizer *SealedUser, user *SealedUser, groups ...*SealedGroup) error {
	groupIDs, err := e.authorizeGroups(authorizer, groups...)
	if err != nil {
		return err
	}

	plainUser, err := user.unseal(e.UserCryptor)
	if err != nil {
		return err
	}
	plainUser.addGroups(groupIDs...)

	*user, err = plainUser.seal(user.ID, e.UserCryptor)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUserFromGroups removes the user from the provided groups. The authorizing user must be a
// member of all the groups. The user is modified in-place.
func (e *Encryptonize) RemoveUserFromGroups(authorizer *SealedUser, user *SealedUser, groups ...*SealedGroup) error {
	groupIDs, err := e.authorizeGroups(authorizer, groups...)
	if err != nil {
		return err
	}

	plainUser, err := user.unseal(e.UserCryptor)
	if err != nil {
		return err
	}
	plainUser.removeGroups(groupIDs...)

	*user, err = plainUser.seal(user.ID, e.UserCryptor)
	if err != nil {
		return err
	}

	return nil
}

////////////////////////////////////////////////////////
//                       Group                        //
////////////////////////////////////////////////////////

// NewGroup creates a new Encryptonize group containing the provided data. The provided user is
// automatically added to the newly created group. The user is modified in-place.
//
// The sealed group is not sensitive data.
func (e *Encryptonize) NewGroup(user *SealedUser, data []byte) (SealedGroup, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return SealedGroup{}, err
	}

	group := newGroup(data)
	sealedGroup, err := (&group).seal(id, e.GroupCryptor)
	if err != nil {
		return SealedGroup{}, err
	}

	plainUser, err := user.unseal(e.UserCryptor)
	if err != nil {
		return SealedGroup{}, err
	}
	plainUser.addGroups(sealedGroup.ID)

	*user, err = plainUser.seal(user.ID, e.UserCryptor)
	if err != nil {
		return SealedGroup{}, err
	}

	return sealedGroup, nil
}

// GetGroupData extracts the data contained in the provided group. The authorizing user must be a
// member of the group.
//
// The returned data may be sensitive.
func (e *Encryptonize) GetGroupData(authorizer *SealedUser, group *SealedGroup) ([]byte, error) {
	plainGroup, err := group.unseal(e.GroupCryptor)
	if err != nil {
		return nil, err
	}

	plainAuthorizer, err := authorizer.unseal(e.UserCryptor)
	if err != nil {
		return nil, err
	}
	if !plainAuthorizer.containsGroups(group.ID) {
		return nil, ErrNotAuthorized
	}

	return plainGroup.Data, nil
}
