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

	"github.com/cybercryptio/d1-lib/crypto"
	"github.com/cybercryptio/d1-lib/data"
	"github.com/cybercryptio/d1-lib/id"
	"github.com/cybercryptio/d1-lib/io"
	"github.com/cybercryptio/d1-lib/key"
)

// Error returned if the caller cannot be authenticated by the Identity Provider.
var ErrNotAuthenticated = errors.New("user not authenticated")

// Error returned if a user tries to access data they are not authorized for.
var ErrNotAuthorized = errors.New("user not authorized")

// Encryptonize is the entry point to the library. All main functionality is exposed through methods
// on this struct.
type Encryptonize struct {
	keyProvider key.Provider
	ioProvider  io.Provider
	idProvider  id.Provider

	objectCryptor crypto.CryptorInterface
	accessCryptor crypto.CryptorInterface
	tokenCryptor  crypto.CryptorInterface
	indexKey      []byte
}

// New creates a new instance of Encryptonize configured with the given providers.
func New(keyProvider key.Provider, ioProvider io.Provider, idProvider id.Provider) (Encryptonize, error) {
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

	return Encryptonize{
		keyProvider:   keyProvider,
		ioProvider:    ioProvider,
		idProvider:    idProvider,
		objectCryptor: &objectCryptor,
		accessCryptor: &accessCryptor,
		tokenCryptor:  &tokenCryptor,
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
func (e *Encryptonize) Encrypt(token string, object *data.Object) (uuid.UUID, error) {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return uuid.Nil, ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeEncrypt) {
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
	access.AddGroups(identity.ID)
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
func (e *Encryptonize) Update(token string, oid uuid.UUID, object *data.Object) error {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeUpdate) {
		return ErrNotAuthorized
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(&identity, id.ScopeUpdate, access)
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
func (e *Encryptonize) Decrypt(token string, oid uuid.UUID) (data.Object, error) {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return data.Object{}, ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeDecrypt) {
		return data.Object{}, ErrNotAuthorized
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return data.Object{}, err
	}

	plainAccess, err := e.authorizeAccess(&identity, id.ScopeDecrypt, access)
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
func (e *Encryptonize) GetAccessGroups(token string, oid uuid.UUID) (map[uuid.UUID]struct{}, error) {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return nil, ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeGetAccessGroups) {
		return nil, ErrNotAuthorized
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return nil, err
	}

	plainAccess, err := e.authorizeAccess(&identity, id.ScopeGetAccessGroups, access)
	if err != nil {
		return nil, err
	}

	return plainAccess.GetGroups(), nil
}

// AddGroupsToAccess appends the provided groups to the object's access list, giving them access to
// the associated object. The authorizing user must be part of the access list.
//
// The input ID is the identifier obtained by previously calling Encrypt.
func (e *Encryptonize) AddGroupsToAccess(token string, oid uuid.UUID, groups ...uuid.UUID) error {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeModifyAccessGroups) {
		return ErrNotAuthorized
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(&identity, id.ScopeModifyAccessGroups, access)
	if err != nil {
		return err
	}
	plainAccess.AddGroups(groups...)

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
func (e *Encryptonize) RemoveGroupsFromAccess(token string, oid uuid.UUID, groups ...uuid.UUID) error {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeModifyAccessGroups) {
		return ErrNotAuthorized
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	plainAccess, err := e.authorizeAccess(&identity, id.ScopeModifyAccessGroups, access)
	if err != nil {
		return err
	}
	plainAccess.RemoveGroups(groups...)

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
func (e *Encryptonize) AuthorizeUser(token string, oid uuid.UUID) error {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeGetAccessGroups) {
		return ErrNotAuthorized
	}

	access, err := e.getSealedAccess(oid)
	if err != nil {
		return err
	}

	_, err = e.authorizeAccess(&identity, id.ScopeGetAccessGroups, access)
	return err
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
