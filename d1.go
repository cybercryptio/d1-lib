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
D1 is a library that provides easy access to data encryption with built in access control.
*/
package d1

import (
	"context"
	"errors"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog"

	"github.com/cybercryptio/d1-lib/v2/crypto"
	"github.com/cybercryptio/d1-lib/v2/data"
	"github.com/cybercryptio/d1-lib/v2/id"
	"github.com/cybercryptio/d1-lib/v2/io"
	"github.com/cybercryptio/d1-lib/v2/key"
)

// Error returned if the caller cannot be authenticated by the Identity Provider.
var ErrNotAuthenticated = errors.New("not authenticated")

// Error returned if the caller tries to access data they are not authorized for.
var ErrNotAuthorized = errors.New("not authorized")

// D1 is the entry point to the library. All main functionality is exposed through methods
// on this struct.
type D1 struct {
	keyProvider key.Provider
	ioProvider  io.Provider
	idProvider  id.Provider

	objectCryptor crypto.CryptorInterface
	accessCryptor crypto.CryptorInterface
	tokenCryptor  crypto.CryptorInterface
}

// New creates a new instance of D1 configured with the given providers.
func New(ctx context.Context, keyProvider key.Provider, ioProvider io.Provider, idProvider id.Provider) (D1, error) {
	log := zerolog.Ctx(ctx)

	log.Debug().Msg("getting keys")
	keys, err := keyProvider.GetKeys(ctx)
	if err != nil {
		return D1{}, err
	}

	log.Debug().Msg("creating object cryptor")
	objectCryptor, err := crypto.NewAESCryptor(keys.KEK)
	if err != nil {
		return D1{}, err
	}
	log.Debug().Msg("creating access cryptor")
	accessCryptor, err := crypto.NewAESCryptor(keys.AEK)
	if err != nil {
		return D1{}, err
	}
	log.Debug().Msg("creating token cryptor")
	tokenCryptor, err := crypto.NewAESCryptor(keys.TEK)
	if err != nil {
		return D1{}, err
	}

	return D1{
		keyProvider:   keyProvider,
		ioProvider:    ioProvider,
		idProvider:    idProvider,
		objectCryptor: &objectCryptor,
		accessCryptor: &accessCryptor,
		tokenCryptor:  &tokenCryptor,
	}, nil
}

////////////////////////////////////////////////////////
//                       Object                       //
////////////////////////////////////////////////////////

// Encrypt creates a new sealed object containing the provided plaintext data as well as an access
// list that controls access to that data. The Identity of the caller is automatically added to the
// access list. To grant access to other callers either specify them in the optional 'groups'
// argument or see AddGroupsToAccess.
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
func (d *D1) Encrypt(ctx context.Context, token string, object *data.Object, groups ...string) (uuid.UUID, error) {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "encrypt").Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeEncrypt)
	if err != nil {
		return uuid.Nil, err
	}

	oid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}
	*log = log.With().Stringer("oid", oid).Logger()

	log.Debug().Msg("sealing object")
	wrappedOEK, sealedObject, err := object.Seal(oid, d.objectCryptor)
	if err != nil {
		return uuid.Nil, err
	}

	log.Debug().Strs("groups", groups).Msg("creating access")
	access := data.NewAccess(wrappedOEK)
	access.AddGroups(append(groups, identity.ID)...)

	log.Debug().Msg("sealing access")
	sealedAccess, err := access.Seal(oid, d.accessCryptor)
	if err != nil {
		return uuid.Nil, err
	}

	// Write data to IO Provider
	if err := d.putSealedObject(ctx, &sealedObject, false); err != nil {
		return uuid.Nil, err
	}
	if err := d.putSealedAccess(ctx, &sealedAccess, false); err != nil {
		return uuid.Nil, err
	}

	return oid, nil
}

// Update creates a new sealed object containing the provided plaintext data but uses a previously
// created access list to control access to that data. The authorizing Identity must be part of the
// provided access list, either directly or through group membership.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// Required scopes:
// - Update
func (d *D1) Update(ctx context.Context, token string, oid uuid.UUID, object *data.Object) error {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "update").Logger()
	*log = log.With().Stringer("oid", oid).Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeUpdate)
	if err != nil {
		return err
	}

	access, err := d.getSealedAccess(ctx, oid)
	if err != nil {
		return err
	}

	plainAccess, err := d.authorizeAccess(ctx, &identity, id.ScopeUpdate, access)
	if err != nil {
		return err
	}

	log.Debug().Msg("sealing object")
	wrappedOEK, sealedObject, err := object.Seal(oid, d.objectCryptor)
	if err != nil {
		return err
	}

	log.Debug().Msg("sealing access")
	plainAccess.WrappedOEK = wrappedOEK
	sealedAccess, err := plainAccess.Seal(oid, d.accessCryptor)
	if err != nil {
		return err
	}

	// Write data to IO Provider
	if err := d.putSealedObject(ctx, &sealedObject, true); err != nil {
		return err
	}
	if err := d.putSealedAccess(ctx, &sealedAccess, true); err != nil {
		return err
	}

	return nil
}

// Decrypt fetches a sealed object and extracts the plaintext. The authorizing Identity must be part of
// the provided access list, either directly or through group membership.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// The unsealed object may contain sensitive data.
//
// Required scopes:
// - Decrypt
func (d *D1) Decrypt(ctx context.Context, token string, oid uuid.UUID) (data.Object, error) {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "decrypt").Logger()
	*log = log.With().Stringer("oid", oid).Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeDecrypt)
	if err != nil {
		return data.Object{}, err
	}

	access, err := d.getSealedAccess(ctx, oid)
	if err != nil {
		return data.Object{}, err
	}

	plainAccess, err := d.authorizeAccess(ctx, &identity, id.ScopeDecrypt, access)
	if err != nil {
		return data.Object{}, err
	}

	object, err := d.getSealedObject(ctx, oid)
	if err != nil {
		return data.Object{}, err
	}

	log.Debug().Msg("unsealing object")
	return object.Unseal(plainAccess.WrappedOEK, d.objectCryptor)
}

// Delete deletes a sealed object. The authorizing Identity must be part of
// the provided access list, either directly or through group membership.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// Required scopes:
// - Delete
func (d *D1) Delete(ctx context.Context, token string, oid uuid.UUID) error {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "delete").Logger()
	*log = log.With().Stringer("oid", oid).Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeDelete)
	if err != nil {
		return err
	}

	access, err := d.getSealedAccess(ctx, oid)
	switch err {
	case nil:
		// Ignore and proceed
	case io.ErrNotFound:
		log.Debug().Msg("object not found")
		// If we can't find the access, that should mean the sealed object
		// doesn't exist, either because it never existed, or it has been completely deleted.
		// Because the sealed access is deleted last as the step in a deletion
		// (see further below) we know that a deleted access entry also implies a deleted object.
		// In either case, what the client wanted has already
		// been achieved, and so we return with no error.
		return nil
	default:
		return err
	}

	if _, err = d.authorizeAccess(ctx, &identity, id.ScopeDelete, access); err != nil {
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
	if err = d.deleteSealedObject(ctx, oid); err != nil {
		return err
	}
	if err = d.deleteSealedAccess(ctx, oid); err != nil {
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
func (d *D1) CreateToken(ctx context.Context, plaintext []byte) (data.SealedToken, error) {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "create token").Logger()

	token := data.NewToken(plaintext, data.TokenValidity)
	log.Debug().Time("expiry", token.ExpiryTime).Msg("token created")
	log.Debug().Msg("sealing token")
	return token.Seal(d.tokenCryptor)
}

// GetTokenContents extracts the plaintext data from a sealed token, provided that the token has not
// expired.
func (d *D1) GetTokenContents(ctx context.Context, token *data.SealedToken) ([]byte, error) {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "get token contents").Logger()

	log.Debug().Time("expiry", token.ExpiryTime).Msg("unsealing token")
	plainToken, err := token.Unseal(d.tokenCryptor)
	if err != nil {
		return nil, err
	}
	return plainToken.Plaintext, nil
}

////////////////////////////////////////////////////////
//                       Access                       //
////////////////////////////////////////////////////////

// GetAccessGroups extracts the set of group IDs contained in the object's access list. The
// authorizing Identity must be part of the access list.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// The set of group IDs is somewhat sensitive data, as it reveals what Identities have access to
// the associated object.
//
// Required scopes:
// - GetAccessGroups
func (d *D1) GetAccessGroups(ctx context.Context, token string, oid uuid.UUID) (map[string]struct{}, error) {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "get access groups").Logger()
	*log = log.With().Stringer("oid", oid).Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeGetAccessGroups)
	if err != nil {
		return nil, err
	}

	access, err := d.getSealedAccess(ctx, oid)
	if err != nil {
		return nil, err
	}

	plainAccess, err := d.authorizeAccess(ctx, &identity, id.ScopeGetAccessGroups, access)
	if err != nil {
		return nil, err
	}

	return plainAccess.GetGroups(), nil
}

// AddGroupsToAccess appends the provided groups to the object's access list, giving them access to
// the associated object. The authorizing Identity must be part of the access list.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// Required scopes:
// - ModifyAccessGroups
func (d *D1) AddGroupsToAccess(ctx context.Context, token string, oid uuid.UUID, groups ...string) error {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "add groups to access").Logger()
	*log = log.With().Stringer("oid", oid).Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeModifyAccessGroups)
	if err != nil {
		return err
	}

	access, err := d.getSealedAccess(ctx, oid)
	if err != nil {
		return err
	}

	plainAccess, err := d.authorizeAccess(ctx, &identity, id.ScopeModifyAccessGroups, access)
	if err != nil {
		return err
	}

	log.Debug().Strs("groups", groups).Msg("adding groups")
	plainAccess.AddGroups(groups...)

	log.Debug().Msg("sealing access")
	*access, err = plainAccess.Seal(oid, d.accessCryptor)
	if err != nil {
		return err
	}

	return d.putSealedAccess(ctx, access, true)
}

// RemoveGroupsFromAccess removes the provided groups from the object's access list, preventing them
// from accessing the associated object. The authorizing Identity must be part of the access object.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// Required scopes:
// - ModifyAccessGroups
func (d *D1) RemoveGroupsFromAccess(ctx context.Context, token string, oid uuid.UUID, groups ...string) error {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "remove groups from access").Logger()
	*log = log.With().Stringer("oid", oid).Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeModifyAccessGroups)
	if err != nil {
		return err
	}

	access, err := d.getSealedAccess(ctx, oid)
	if err != nil {
		return err
	}

	plainAccess, err := d.authorizeAccess(ctx, &identity, id.ScopeModifyAccessGroups, access)
	if err != nil {
		return err
	}

	log.Debug().Strs("groups", groups).Msg("removing groups")
	plainAccess.RemoveGroups(groups...)

	log.Debug().Msg("sealing access")
	*access, err = plainAccess.Seal(oid, d.accessCryptor)
	if err != nil {
		return err
	}

	return d.putSealedAccess(ctx, access, true)
}

// AuthorizeIdentity checks whether the provided Identity is part of the object's access list, i.e. whether
// they are authorized to access the associated object. An error is returned if the Identity is not
// authorized.
//
// The input ID is the identifier obtained by previously calling Encrypt.
//
// Required scopes:
// - GetAccessGroups
func (d *D1) AuthorizeIdentity(ctx context.Context, token string, oid uuid.UUID) error {
	log := zerolog.Ctx(ctx)
	*log = log.With().Str("method", "authorize identity").Logger()
	*log = log.With().Stringer("oid", oid).Logger()

	identity, err := d.verifyAccess(ctx, token, id.ScopeGetAccessGroups)
	if err != nil {
		return err
	}

	access, err := d.getSealedAccess(ctx, oid)
	if err != nil {
		return err
	}

	_, err = d.authorizeAccess(ctx, &identity, id.ScopeGetAccessGroups, access)
	return err
}
