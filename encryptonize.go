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
	"errors"

	"github.com/gofrs/uuid"

	"encryptonize/crypto"
)

type Config struct {
	KEK, AEK, TEK, UEK, GEK []byte
}

type Encryptonize struct {
	objectCryptor, accessCryptor, tokenCryptor, userCryptor, groupCryptor crypto.CryptorInterface
}

func New(config Config) (Encryptonize, error) {
	objectCryptor, err := crypto.NewAESCryptor(config.KEK)
	if err != nil {
		return Encryptonize{}, err
	}
	accessCryptor, err := crypto.NewAESCryptor(config.AEK)
	if err != nil {
		return Encryptonize{}, err
	}
	tokenCryptor, err := crypto.NewAESCryptor(config.TEK)
	if err != nil {
		return Encryptonize{}, err
	}
	userCryptor, err := crypto.NewAESCryptor(config.UEK)
	if err != nil {
		return Encryptonize{}, err
	}
	groupCryptor, err := crypto.NewAESCryptor(config.GEK)
	if err != nil {
		return Encryptonize{}, err
	}

	return Encryptonize{&objectCryptor, &accessCryptor, &tokenCryptor, &userCryptor, &groupCryptor}, nil
}

func (e *Encryptonize) Encrypt(object *Object, user *SealedUser) (SealedObject, SealedAccess, error) {
	if !user.verify(e.userCryptor) {
		return SealedObject{}, SealedAccess{}, errors.New("User not authorized")
	}

	wrappedOEK, sealedObject, err := object.seal(e.objectCryptor)
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}

	access := newAccess(wrappedOEK)
	access.addGroups(user.ID)
	sealedAccess, err := access.seal(sealedObject.ID, e.accessCryptor)
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}

	return sealedObject, sealedAccess, nil
}

func (e *Encryptonize) Update(authorizer *SealedUser, object *Object, access *SealedAccess) (SealedObject, error) {
	plainAccess, err := e.authorize(authorizer, access)
	if err != nil {
		return SealedObject{}, err
	}

	wrappedOEK, sealedObject, err := object.seal(e.objectCryptor)
	if err != nil {
		return SealedObject{}, err
	}

	plainAccess.WrappedOEK = wrappedOEK
	sealedAccess, err := plainAccess.seal(sealedObject.ID, e.accessCryptor)
	if err != nil {
		return SealedObject{}, err
	}
	*access = sealedAccess

	return sealedObject, nil
}

func (e *Encryptonize) Decrypt(authorizer *SealedUser, object *SealedObject, access *SealedAccess) (Object, error) {
	plainAccess, err := e.authorize(authorizer, access)
	if err != nil {
		return Object{}, err
	}

	return object.unseal(plainAccess.WrappedOEK, e.objectCryptor)
}

func (e *Encryptonize) AddGroupsToAccess(authorizer *SealedUser, access *SealedAccess, groups ...*SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorize(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.addGroups(groupIDs...)

	*access, err = plainAccess.seal(access.ID, e.accessCryptor)
	return err
}

func (e *Encryptonize) RemoveGroupsFromAccess(authorizer *SealedUser, access *SealedAccess, groups ...*SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorize(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.removeGroups(groupIDs...)

	*access, err = plainAccess.seal(access.ID, e.accessCryptor)
	return err
}

func (e *Encryptonize) NewUser(groups ...uuid.UUID) (SealedUser, string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return SealedUser{}, "", err
	}

	user, pwd, err := newUser(groups...)
	if err != nil {
		return SealedUser{}, "", err
	}

	sealedUser, err := user.seal(id, e.userCryptor)
	if err != nil {
		return SealedUser{}, "", err
	}

	return sealedUser, pwd, nil
}

func (e *Encryptonize) AddUserToGroups(authorizer *SealedUser, user *SealedUser, groups ...*SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	plainAuthorizer, err := authorizer.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	if !plainAuthorizer.containsGroups(groupIDs...) {
		return errors.New("User not authorized")
	}

	plainUser, err := user.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	plainUser.addGroups(groupIDs...)

	*user, err = plainUser.seal(user.ID, e.userCryptor)
	if err != nil {
		return err
	}

	return nil
}

func (e *Encryptonize) RemoveUserFromGroups(authorizer *SealedUser, user *SealedUser, groups ...*SealedGroup) error {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return err
	}

	plainAuthorizer, err := authorizer.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	if !plainAuthorizer.containsGroups(groupIDs...) {
		return errors.New("User not authorized")
	}

	plainUser, err := user.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	plainUser.removeGroups(groupIDs...)

	*user, err = plainUser.seal(user.ID, e.userCryptor)
	if err != nil {
		return err
	}

	return nil
}

// NewGroup creates a group with the specified scopes in the authStorage
func (e *Encryptonize) NewGroup(scopes ScopeType) (SealedGroup, error) {
	return (&Group{scopes}).seal(e.groupCryptor)
}

func (e *Encryptonize) authorize(authorizer *SealedUser, access *SealedAccess) (Access, error) {
	plainAccess, err := access.unseal(e.accessCryptor)
	if err != nil {
		return Access{}, err
	}

	plainAuthorizer, err := authorizer.unseal(e.userCryptor)
	if err != nil {
		return Access{}, err
	}

	for _, id := range plainAuthorizer.getGroups() {
		if plainAccess.containsGroups(id) {
			return plainAccess, nil
		}
	}
	return Access{}, errors.New("User not authorized")
}

func (e *Encryptonize) verifyGroups(groups ...*SealedGroup) ([]uuid.UUID, error) {
	groupIDs := make([]uuid.UUID, 0, len(groups))
	for _, group := range groups {
		if !group.verify(e.groupCryptor) {
			return nil, errors.New("Invalid group")
		}
		groupIDs = append(groupIDs, group.ID)
	}
	return groupIDs, nil
}