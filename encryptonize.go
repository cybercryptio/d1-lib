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
	// Used for key wrapping
	KEK []byte

	// Used for access object encryption
	AEK []byte

	// Used for token encryption
	TEK []byte

	// Used for confidential user data encryption
	UEK []byte

	// Used for confidential group data encryption
	GEK []byte
}

type Encryptonize struct {
	objectCryptor crypto.CryptorInterface
	accessCryptor crypto.CryptorInterface
	tokenCryptor  crypto.CryptorInterface
	userCryptor   crypto.CryptorInterface
	groupCryptor  crypto.CryptorInterface
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
	access.addGroup(user.ID)
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

func (e *Encryptonize) AddGroupToAccess(authorizer *SealedUser, group *SealedGroup, access *SealedAccess) error {
	if !group.verify(e.groupCryptor) {
		return errors.New("User not authorized")
	}

	plainAccess, err := e.authorize(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.addGroup(group.ID)

	*access, err = plainAccess.seal(access.ID, e.accessCryptor)
	return err
}

func (e *Encryptonize) RemoveGroupFromAccess(authorizer *SealedUser, group *SealedGroup, access *SealedAccess) error {
	if !group.verify(e.groupCryptor) {
		return errors.New("User not authorized")
	}

	plainAccess, err := e.authorize(authorizer, access)
	if err != nil {
		return err
	}
	plainAccess.removeGroup(group.ID)

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

func (e *Encryptonize) AddUserToGroup(authorizer *SealedUser, user *SealedUser, group *SealedGroup) error {
	if !group.verify(e.groupCryptor) {
		return errors.New("User not authorized")
	}

	plainAuthorizer, err := authorizer.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	if !plainAuthorizer.containsGroup(group.ID) {
		return errors.New("User not authorized")
	}

	plainUser, err := user.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	plainUser.addGroup(group.ID)

	*user, err = plainUser.seal(user.ID, e.userCryptor)
	if err != nil {
		return err
	}

	return nil
}

func (e *Encryptonize) RemoveUserFromGroup(authorizer *SealedUser, user *SealedUser, group *SealedGroup) error {
	if !group.verify(e.groupCryptor) {
		return errors.New("User not authorized")
	}

	plainAuthorizer, err := authorizer.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	if !plainAuthorizer.containsGroup(group.ID) {
		return errors.New("User not authorized")
	}

	plainUser, err := user.unseal(e.userCryptor)
	if err != nil {
		return err
	}
	plainUser.removeGroup(group.ID)

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
		if plainAccess.containsGroup(id) {
			return plainAccess, nil
		}
	}
	return Access{}, errors.New("User not authorized")
}
