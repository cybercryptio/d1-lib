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
	dataCryptor   crypto.CryptorInterface
	accessCryptor crypto.CryptorInterface
	tokenCryptor  crypto.CryptorInterface
	userCryptor   crypto.CryptorInterface
	groupCryptor  crypto.CryptorInterface
}

func New(config Config) (Encryptonize, error) {
	dataCryptor, err := crypto.NewAESCryptor(config.KEK)
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

	return Encryptonize{dataCryptor, accessCryptor, tokenCryptor, userCryptor, groupCryptor}, nil
}

func (e *Encryptonize) Encrypt(object *Object, user *SealedUser) (SealedObject, SealedAccess, error) {
	objectID, err := uuid.NewV4()
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}

	wrappedOEK, ciphertext, err := e.dataCryptor.Encrypt(object.Plaintext, object.AssociatedData)
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}
	sealedObject := SealedObject{ciphertext, object.AssociatedData, objectID}

	access := newAccess(user.ID, wrappedOEK)
	wrappedKey, ciphertext, err := e.accessCryptor.EncodeAndEncrypt(access, objectID.Bytes())
	if err != nil {
		return SealedObject{}, SealedAccess{}, err
	}
	sealedAccess := SealedAccess{objectID, ciphertext, wrappedKey}

	return sealedObject, sealedAccess, nil
}

func (e *Encryptonize) Decrypt(object *SealedObject, access *SealedAccess, user *SealedUser) (Object, error) {
	plainAccess := &Access{}
	err := e.accessCryptor.DecodeAndDecrypt(plainAccess, access.wrappedKey, access.ciphertext, access.ID.Bytes())
	if err != nil {
		return Object{}, err
	}

	plainUser := &User{}
	err = e.userCryptor.DecodeAndDecrypt(plainUser, user.wrappedKey, user.ciphertext, user.ID.Bytes())
	if err != nil {
		return Object{}, err
	}

	allowed := false
	for _, id := range plainUser.getGroups() {
		allowed = allowed || plainAccess.containsGroup(id)
	}
	if !allowed {
		return Object{}, errors.New("User not authorized")
	}

	plaintext, err := e.dataCryptor.Decrypt(plainAccess.getWOEK(), object.ciphertext, object.AssociatedData)
	if err != nil {
		return Object{}, err
	}

	return Object{
		Plaintext:      plaintext,
		AssociatedData: object.AssociatedData,
	}, nil
}

func (e *Encryptonize) AddGroupToAccess(user *SealedUser, group *SealedGroup, access *SealedAccess) error {
	plainAccess := &Access{}
	err := e.accessCryptor.DecodeAndDecrypt(plainAccess, access.wrappedKey, access.ciphertext, access.ID.Bytes())
	if err != nil {
		return err
	}

	plainUser := &User{}
	err = e.userCryptor.DecodeAndDecrypt(plainUser, user.wrappedKey, user.ciphertext, user.ID.Bytes())
	if err != nil {
		return err
	}

	allowed := false
	for _, id := range plainUser.getGroups() {
		allowed = allowed || plainAccess.containsGroup(id)
	}
	if !allowed {
		return errors.New("User not authorized")
	}

	_, err = e.groupCryptor.Decrypt(group.wrappedKey, group.ciphertext, group.ID.Bytes())
	if err != nil {
		return err
	}
	plainAccess.addGroup(group.ID)

	wrappedKey, ciphertext, err := e.accessCryptor.EncodeAndEncrypt(plainAccess, access.ID.Bytes())
	if err != nil {
		return err
	}
	access.wrappedKey = wrappedKey
	access.ciphertext = ciphertext

	return nil
}

func (e *Encryptonize) RemoveGroupFromAccess(user *SealedUser, group *SealedGroup, access *SealedAccess) error {
	plainAccess := &Access{}
	err := e.accessCryptor.DecodeAndDecrypt(plainAccess, access.wrappedKey, access.ciphertext, access.ID.Bytes())
	if err != nil {
		return err
	}

	plainUser := &User{}
	err = e.userCryptor.DecodeAndDecrypt(plainUser, user.wrappedKey, user.ciphertext, user.ID.Bytes())
	if err != nil {
		return err
	}

	allowed := false
	for _, id := range plainUser.getGroups() {
		allowed = allowed || plainAccess.containsGroup(id)
	}
	if !allowed {
		return errors.New("User not authorized")
	}

	_, err = e.groupCryptor.Decrypt(group.wrappedKey, group.ciphertext, group.ID.Bytes())
	if err != nil {
		return err
	}
	plainAccess.removeGroup(group.ID)

	wrappedKey, ciphertext, err := e.accessCryptor.EncodeAndEncrypt(plainAccess, access.ID.Bytes())
	if err != nil {
		return err
	}
	access.wrappedKey = wrappedKey
	access.ciphertext = ciphertext

	return nil
}

func (e *Encryptonize) NewUser(groups ...uuid.UUID) (SealedUser, string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return SealedUser{}, "", err
	}

	// user password creation
	pwd, salt, err := crypto.GenerateUserPassword()
	if err != nil {
		return SealedUser{}, "", err
	}

	groupMap := make(map[uuid.UUID]bool)
	for _, g := range groups {
		groupMap[g] = true
	}

	user := &User{
		hashedPassword: crypto.HashPassword(pwd, salt),
		salt:           salt,
		groups:         groupMap,
	}

	wrappedKey, ciphertext, err := e.userCryptor.EncodeAndEncrypt(user, id.Bytes())
	if err != nil {
		return SealedUser{}, "", err
	}

	return SealedUser{id, ciphertext, wrappedKey}, pwd, nil
}

func (e *Encryptonize) AddUserToGroup(authorizer *SealedUser, user *SealedUser, group *SealedGroup) error {
	plainAuthorizer := &User{}
	err := e.userCryptor.DecodeAndDecrypt(plainAuthorizer, authorizer.wrappedKey, authorizer.ciphertext, authorizer.ID.Bytes())
	if err != nil {
		return err
	}
	_, err = e.groupCryptor.Decrypt(group.wrappedKey, group.ciphertext, group.ID.Bytes())
	if err != nil {
		return err
	}

	if !plainAuthorizer.containsGroup(group.ID) {
		return errors.New("User not authorized")
	}

	plainUser := &User{}
	err = e.userCryptor.DecodeAndDecrypt(plainUser, user.wrappedKey, user.ciphertext, user.ID.Bytes())
	if err != nil {
		return err
	}
	plainUser.addGroup(group.ID)

	wrappedKey, ciphertext, err := e.userCryptor.EncodeAndEncrypt(plainUser, user.ID.Bytes())
	if err != nil {
		return err
	}
	user.wrappedKey = wrappedKey
	user.ciphertext = ciphertext

	return nil
}

func (e *Encryptonize) RemoveUserFromGroup(authorizer *SealedUser, user *SealedUser, group *SealedGroup) error {
	plainAuthorizer := &User{}
	err := e.userCryptor.DecodeAndDecrypt(plainAuthorizer, authorizer.wrappedKey, authorizer.ciphertext, authorizer.ID.Bytes())
	if err != nil {
		return err
	}
	_, err = e.groupCryptor.Decrypt(group.wrappedKey, group.ciphertext, group.ID.Bytes())
	if err != nil {
		return err
	}

	if !plainAuthorizer.containsGroup(group.ID) {
		return errors.New("User not authorized")
	}

	plainUser := &User{}
	err = e.userCryptor.DecodeAndDecrypt(plainUser, user.wrappedKey, user.ciphertext, user.ID.Bytes())
	if err != nil {
		return err
	}
	plainUser.removeGroup(group.ID)

	wrappedKey, ciphertext, err := e.userCryptor.EncodeAndEncrypt(plainUser, user.ID.Bytes())
	if err != nil {
		return err
	}
	user.wrappedKey = wrappedKey
	user.ciphertext = ciphertext

	return nil
}

// NewGroup creates a group with the specified scopes in the authStorage
func (e *Encryptonize) NewGroup(scopes ScopeType) (SealedGroup, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return SealedGroup{}, err
	}
	group := &Group{scopes}
	wrappedKey, ciphertext, err := e.groupCryptor.EncodeAndEncrypt(group, id.Bytes())
	if err != nil {
		return SealedGroup{}, err
	}
	return SealedGroup{id, ciphertext, wrappedKey}, nil
}
