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
//
// Required scopes:
// - Encrypt
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
//
// Required scopes:
// - Update
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
//
// Required scopes:
// - Decrypt
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

// Delete deletes a sealed object. The authorizing user must be part of
// the provided access list, either directly or through group membership.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// Required scopes:
// - Delete
func (e *Encryptonize) Delete(token string, oid uuid.UUID) error {
	identity, err := e.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeDelete) {
		return ErrNotAuthorized
	}

	access, err := e.getSealedAccess(oid)
	switch err {
	case nil:
		// Ignore and proceed
	case io.ErrNotFound:
		// If we can't find the access, that should mean the sealed object
		// doesn't exist. In which case, what the client wanted, has already
		// been achived, and so we return with no error.
		return nil
	default:
		return err
	}

	if _, err = e.authorizeAccess(&identity, id.ScopeDelete, access); err != nil {
		return err
	}

	// Delete data from IO Provider
	// NOTE: It is a conscious decision to delete the sealed object first,
	// then the sealed access.
	// This way, if the deletion of the sealed object succeeds, but the
	// deletion of the sealed access fails, we can retry with another delete
	// to get rid of the dangling access entry.
	// If we deleted the access first, and then fail to delete the object,
	// we would have a dangling object we can't access, and therefore can't delete.
	if err = e.deleteSealedObject(oid); err != nil {
		return err
	}
	if err = e.deleteSealedAccess(oid); err != nil {
		return err
	}

	return nil
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
//
// Required scopes:
// - GetAccessGroups
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
//
// Required scopes:
// - ModifyAccessGroups
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
//
// Required scopes:
// - ModifyAccessGroups
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
//
// Required scopes:
// - GetAccessGroups
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
