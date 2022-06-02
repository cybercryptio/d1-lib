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

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
	"github.com/cyber-crypt-com/encryptonize-lib/data"
	"github.com/cyber-crypt-com/encryptonize-lib/io"
	"github.com/cyber-crypt-com/encryptonize-lib/key"
)

// Error returned if a user tries to access data they are not authorized for.
var ErrNotAuthorized = errors.New("user not authorized")

// Encryptonize is the entry point to the library. All main functionality is exposed through methods
// on this struct.
type Encryptonize struct {
	keyProvider key.Provider
	ioProvider  io.Provider

	objectCryptor crypto.CryptorInterface
	accessCryptor crypto.CryptorInterface
	tokenCryptor  crypto.CryptorInterface
	userCryptor   crypto.CryptorInterface
	groupCryptor  crypto.CryptorInterface
	indexKey      []byte
}

// New creates a new instance of Encryptonize configured with the given providers.
func New(keyProvider key.Provider, ioProvider io.Provider) (Encryptonize, error) {
	keys, err := keyProvider.GetKeys()
	if err != nil {
		return Encryptonize{}, err
	}

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

	return Encryptonize{
		keyProvider:   keyProvider,
		ioProvider:    ioProvider,
		objectCryptor: &objectCryptor,
		accessCryptor: &accessCryptor,
		tokenCryptor:  &tokenCryptor,
		userCryptor:   &userCryptor,
		groupCryptor:  &groupCryptor,
		indexKey:      keys.IEK,
	}, nil
}

////////////////////////////////////////////////////////
//                       Object                       //
////////////////////////////////////////////////////////

// Encrypt creates a new sealed object containing the provided plaintext data as well as an access
// list that controls access to that data. The calling user is automatically added to the access
// list. To grant other users access, see AddGroupsToAccess and AddUserToGroups.
//
// The returned ID is the unique identifier of the sealed object. It is used to identify the object
// and related data about the object to the IO Provider, and needs to be provided when decrypting
// the object.
//
// For all practical purposes, the size of the ciphertext in the SealedObject is len(plaintext) + 48
// bytes.
func (e *Encryptonize) Encrypt(user *data.SealedUser, object *data.Object) (uuid.UUID, error) {
	if !user.Verify(e.userCryptor) {
		return uuid.Nil, ErrNotAuthorized
	}

	oid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	wrappedOEK, sealedObject, err := object.Seal(oid, e.objectCryptor)
	if err != nil {
		return uuid.Nil, err
	}

	access := data.NewAccess(wrappedOEK)
	access.AddGroups(user.ID)
	sealedAccess, err := access.Seal(oid, e.accessCryptor)
	if err != nil {
		return uuid.Nil, err
	}

	// Write data to IO Provider
	if err := e.putSealedObject(&sealedObject, false); err != nil {
		return uuid.Nil, err
	}
	if err := e.putSealedAccess(&sealedAccess, false); err != nil {
		return uuid.Nil, err
	}

	return oid, nil
}

// Update creates a new sealed object containing the provided plaintext data but uses a previously
// created access list to control access to that data. The authorizing user must be part of the
// provided access list, either directly or through group membership.
//
// The input ID is the identifier obtained by previously calling Encrypt.
func (e *Encryptonize) Update(authorizer *data.SealedUser, oid uuid.UUID, object *data.Object) error {
	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return err
	}

	wrappedOEK, sealedObject, err := object.Seal(oid, e.objectCryptor)
	if err != nil {
		return err
	}

	plainAccess.WrappedOEK = wrappedOEK
	sealedAccess, err := plainAccess.Seal(oid, e.accessCryptor)
	if err != nil {
		return err
	}

	// Write data to IO Provider
	if err := e.putSealedObject(&sealedObject, true); err != nil {
		return err
	}
	if err := e.putSealedAccess(&sealedAccess, true); err != nil {
		return err
	}

	return nil
}

// Decrypt fetches a sealed object and extracts the plaintext. The authorizing user must be part of
// the provided access list, either directly or through group membership.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// The unsealed object may contain sensitive data.
func (e *Encryptonize) Decrypt(authorizer *data.SealedUser, oid uuid.UUID) (data.Object, error) {
	access, err := e.getSealedAccess(oid)
	if err != nil {
		return data.Object{}, err
	}

	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return data.Object{}, err
	}

	object, err := e.getSealedObject(oid)
	if err != nil {
		return data.Object{}, err
	}
	return object.Unseal(plainAccess.WrappedOEK, e.objectCryptor)
}

////////////////////////////////////////////////////////
//                       Token                        //
////////////////////////////////////////////////////////

// CreateToken encapsulates the provided plaintext data in an opaque, self contained token with an
// expiry time given by TokenValidity.
//
// The contents of the token can be validated and retrieved with the GetTokenContents method.
func (e *Encryptonize) CreateToken(plaintext []byte) (data.SealedToken, error) {
	token := data.NewToken(plaintext, data.TokenValidity)
	return token.Seal(e.tokenCryptor)
}

// GetTokenContents extracts the plaintext data from a sealed token, provided that the token has not
// expired.
func (e *Encryptonize) GetTokenContents(token *data.SealedToken) ([]byte, error) {
	plainToken, err := token.Unseal(e.tokenCryptor)
	if err != nil {
		return nil, err
	}
	return plainToken.Plaintext, nil
}

////////////////////////////////////////////////////////
//                       Access                       //
////////////////////////////////////////////////////////

// GetAccessGroups extracts the set of group IDs contained in the object's access list. The
// authorizing user must be part of the access list.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// The set of group IDs is somewhat sensitive data, as it reveals what groups/users have access to
// the associated object.
func (e *Encryptonize) GetAccessGroups(authorizer *data.SealedUser, oid uuid.UUID) (map[uuid.UUID]struct{}, error) {
	access, err := e.getSealedAccess(oid)
	if err != nil {
		return nil, err
	}

	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return nil, err
	}
	return plainAccess.GetGroups(), nil
}

// AddGroupsToAccess appends the provided groups to the object's access list, giving them access to
// the associated object. The authorizing user must be part of the access list.
//
// The input ID is the identifier obtained by previously calling Encrypt.
func (e *Encryptonize) AddGroupsToAccess(authorizer *data.SealedUser, oid uuid.UUID, groups ...*data.SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.AddGroups(groupIDs...)

	*access, err = plainAccess.Seal(oid, e.accessCryptor)
	if err != nil {
		return err
	}

	return e.putSealedAccess(access, true)
}

// RemoveGroupsFromAccess removes the provided groups from the object's access list, preventing them
// from accessing the associated object. The authorizing user must be part of the access object.
//
// The input ID is the identifier obtained by previously calling Encrypt.
func (e *Encryptonize) RemoveGroupsFromAccess(authorizer *data.SealedUser, oid uuid.UUID, groups ...*data.SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.RemoveGroups(groupIDs...)

	*access, err = plainAccess.Seal(oid, e.accessCryptor)
	if err != nil {
		return err
	}

	return e.putSealedAccess(access, true)
}

// AuthorizeUser checks whether the provided user is part of the object's access list, i.e. whether
// they are authorized to access the associated object. An error is returned if the user is not
// authorized.
//
// The input ID is the identifier obtained by previously calling Encrypt.
func (e *Encryptonize) AuthorizeUser(user *data.SealedUser, oid uuid.UUID) error {
	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	_, err = e.authorizeAccess(user, access)
	return err
}

////////////////////////////////////////////////////////
//                        User                        //
////////////////////////////////////////////////////////

// NewUser creates a new Encryptonize user as well as an initial group for that user. The newly
// created user and group have the same ID. The user's own group contains the provided data, and the
// user is added to any additional groups provided. A randomly generated password is also created
// and returned to the caller.
//
// The SealedUser object acts as credentials for decryption so it should only be accessed by
// authenticated users.
func (e *Encryptonize) NewUser(userData []byte, groups ...*data.SealedGroup) (data.SealedUser, data.SealedGroup, string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return data.SealedUser{}, data.SealedGroup{}, "", err
	}

	return e.NewUserWithID(id, userData, groups...)
}

// NewUserWithID creates a new Encryptonize user as well as an initial group for that user, both
// having the provided ID. The user's own group contains the provided data, and the user is added to
// any additional groups provided. A randomly generated password is also created and returned to the
// caller.
//
// The SealedUser object acts as credentials for decryption so it should only be accessed by
// authenticated users.
func (e *Encryptonize) NewUserWithID(id uuid.UUID, userData []byte, groups ...*data.SealedGroup) (data.SealedUser, data.SealedGroup, string, error) {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return data.SealedUser{}, data.SealedGroup{}, "", err
	}

	group := data.NewGroup(userData)
	sealedGroup, err := (&group).Seal(id, e.groupCryptor)
	if err != nil {
		return data.SealedUser{}, data.SealedGroup{}, "", err
	}

	user, pwd, err := data.NewUser(append(groupIDs, id)...)
	if err != nil {
		return data.SealedUser{}, data.SealedGroup{}, "", err
	}

	sealedUser, err := user.Seal(id, e.userCryptor)
	if err != nil {
		return data.SealedUser{}, data.SealedGroup{}, "", err
	}

	return sealedUser, sealedGroup, pwd, nil
}

// GetUserGroups extracts user's set of group IDs.
//
// The set of group IDs is somewhat sensitive data, as it reveals what groups the user is a member
// of.
func (e *Encryptonize) GetUserGroups(user *data.SealedUser) (map[uuid.UUID]struct{}, error) {
	plainUser, err := user.Unseal(e.userCryptor)
	if err != nil {
		return nil, err
	}
	return plainUser.GetGroups(), nil
}

// AuthenticateUser checks whether the password provided matches the user. If not, an error is
// returned.
func (e *Encryptonize) AuthenticateUser(user *data.SealedUser, password string) error {
	plainUser, err := user.Unseal(e.userCryptor)
	if err != nil {
		return err
	}
	if err := plainUser.Authenticate(password); err != nil {
		return err
	}
	return nil
}

// ChangeUserPassword authenticates the provided sealed user with the given password and generates a new password for the user.
// It modifies the user object in place and returns the generated password.
//
// Any copies of the old sealed user must be disposed of.
func (e *Encryptonize) ChangeUserPassword(user *data.SealedUser, oldPassword string) (string, error) {
	plainUser, err := user.Unseal(e.userCryptor)
	if err != nil {
		return "", err
	}

	newPwd, err := plainUser.ChangePassword(oldPassword)
	if err != nil {
		return "", err
	}

	*user, err = plainUser.Seal(user.ID, e.userCryptor)
	if err != nil {
		return "", err
	}

	return newPwd, nil
}

// AddUserToGroups adds the user to the provided groups. The authorizing user must be a member of
// all the groups. The user is modified in-place.
func (e *Encryptonize) AddUserToGroups(authorizer *data.SealedUser, user *data.SealedUser, groups ...*data.SealedGroup) error {
	groupIDs, err := e.authorizeGroups(authorizer, groups...)
	if err != nil {
		return err
	}

	plainUser, err := user.Unseal(e.userCryptor)
	if err != nil {
		return err
	}
	plainUser.AddGroups(groupIDs...)

	*user, err = plainUser.Seal(user.ID, e.userCryptor)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUserFromGroups removes the user from the provided groups. The authorizing user must be a
// member of all the groups. The user is modified in-place.
func (e *Encryptonize) RemoveUserFromGroups(authorizer *data.SealedUser, user *data.SealedUser, groups ...*data.SealedGroup) error {
	groupIDs, err := e.authorizeGroups(authorizer, groups...)
	if err != nil {
		return err
	}

	plainUser, err := user.Unseal(e.userCryptor)
	if err != nil {
		return err
	}
	plainUser.RemoveGroups(groupIDs...)

	*user, err = plainUser.Seal(user.ID, e.userCryptor)
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
func (e *Encryptonize) NewGroup(user *data.SealedUser, groupData []byte) (data.SealedGroup, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return data.SealedGroup{}, err
	}

	group := data.NewGroup(groupData)
	sealedGroup, err := (&group).Seal(id, e.groupCryptor)
	if err != nil {
		return data.SealedGroup{}, err
	}

	plainUser, err := user.Unseal(e.userCryptor)
	if err != nil {
		return data.SealedGroup{}, err
	}
	plainUser.AddGroups(sealedGroup.ID)

	*user, err = plainUser.Seal(user.ID, e.userCryptor)
	if err != nil {
		return data.SealedGroup{}, err
	}

	return sealedGroup, nil
}

// GetGroupData extracts the data contained in the provided group. The authorizing user must be a
// member of the group.
//
// The returned data may be sensitive.
func (e *Encryptonize) GetGroupData(authorizer *data.SealedUser, group *data.SealedGroup) ([]byte, error) {
	plainGroup, err := group.Unseal(e.groupCryptor)
	if err != nil {
		return nil, err
	}

	plainAuthorizer, err := authorizer.Unseal(e.userCryptor)
	if err != nil {
		return nil, err
	}
	if !plainAuthorizer.ContainsGroups(group.ID) {
		return nil, ErrNotAuthorized
	}

	return plainGroup.Data, nil
}

////////////////////////////////////////////////////////
//                       Index                        //
////////////////////////////////////////////////////////

// NewIndex creates a new index that can be used to map keywords to IDs (e.g. documents). This
// means that the index can be used to keep track of which keywords are contained in which IDs.
func (e *Encryptonize) NewIndex() data.Index {
	return data.NewIndex()
}

// Add adds the keyword/ID pair to index i.
func (e *Encryptonize) Add(keyword, id string, i *data.Index) error {
	if err := i.Add(e.indexKey, keyword, id); err != nil {
		return err
	}

	return nil
}

// Search finds all IDs that contain the given keyword and returns them in plaintext.
func (e *Encryptonize) Search(keyword string, i *data.Index) ([]string, error) {
	decryptedIDs, err := i.Search(e.indexKey, keyword)
	if err != nil {
		return nil, err
	}

	return decryptedIDs, nil
}
