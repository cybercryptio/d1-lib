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

package d1

import (
	"context"
	"errors"

	"github.com/gofrs/uuid"
	json "github.com/json-iterator/go"

	"github.com/cybercryptio/d1-lib/v2/data"
	"github.com/cybercryptio/d1-lib/v2/id"
	"github.com/cybercryptio/d1-lib/v2/io"
	"github.com/cybercryptio/d1-lib/v2/log"
)

// verifyAccess verifies the caller. It verifies both that the caller is authenticated by the
// Identity Provider, and that the caller has the necessary scopes.
func (d *D1) verifyAccess(ctx context.Context, token string, scope id.Scope) (id.Identity, error) {
	log.Ctx(ctx).Debug().Msg("authenticating caller")
	identity, err := d.idProvider.GetIdentity(ctx, token)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Msg("authentication failed")
		return id.Identity{}, ErrNotAuthenticated
	}
	log.WithUserID(ctx, identity.ID)

	log.Ctx(ctx).Debug().Msg("authorizing caller")
	if !identity.Scopes.Contains(scope) {
		log.Ctx(ctx).Debug().Stringer("scope", scope).Msg("scope missing")
		return id.Identity{}, ErrNotAuthorized
	}

	return identity, nil
}

// authorizeAccess checks whether the authorizing Identity is allowed to access the provided access
// object. If so, the unsealed access object is returned.
//
// An Identity is authorized to access an object if at least one of the following is true:
//   - The the Identity's ID is part of the Access and the Identity's scope contains the
//     required scope.
//   - One of the Identity's group IDs is part of the Access and that group's scope contains the required
//     scope.
func (d *D1) authorizeAccess(ctx context.Context, identity *id.Identity, scopes id.Scope, sealedAccess *data.SealedAccess) (data.Access, error) {
	log.Ctx(ctx).Debug().Msg("authorizing access")

	plainAccess, err := sealedAccess.Unseal(d.accessCryptor)
	if err != nil {
		return data.Access{}, err
	}

	for gid := range identity.GetIDs() {
		if plainAccess.ContainsGroups(gid) && identity.GetIDScope(gid).Contains(scopes) {
			return plainAccess, nil
		}
	}
	return data.Access{}, ErrNotAuthorized
}

// putSealedObject encodes a sealed object and sends it to the IO Provider, either as a "Put" or an
// "Update".
func (d *D1) putSealedObject(ctx context.Context, object *data.SealedObject, update bool) error {
	objectBytes, err := json.Marshal(object)
	if err != nil {
		return err
	}

	if update {
		log.Ctx(ctx).Debug().Msg("updating stored object")
		err := d.ioProvider.Update(ctx, object.OID.Bytes(), io.DataTypeSealedObject, objectBytes)
		if errors.Is(err, io.ErrNotFound) {
			return ErrObjectNotFound
		}
		return err
	}

	log.Ctx(ctx).Debug().Msg("storing new object")
	err = d.ioProvider.Put(ctx, object.OID.Bytes(), io.DataTypeSealedObject, objectBytes)
	if errors.Is(err, io.ErrAlreadyExists) {
		return ErrObjectAlreadyExists
	}
	return err
}

// getSealedObject fetches bytes from the IO Provider and decodes them into a sealed object.
func (d *D1) getSealedObject(ctx context.Context, oid uuid.UUID) (*data.SealedObject, error) {
	log.Ctx(ctx).Debug().Msg("getting stored object")

	objectBytes, err := d.ioProvider.Get(ctx, oid.Bytes(), io.DataTypeSealedObject)
	if errors.Is(err, io.ErrNotFound) {
		return nil, ErrObjectNotFound
	}
	if err != nil {
		return nil, err
	}

	object := &data.SealedObject{}
	if err := json.Unmarshal(objectBytes, object); err != nil {
		return nil, err
	}

	object.OID = oid
	return object, nil
}

// deleteSealedObject deletes a sealed object from the IO Provider.
func (d *D1) deleteSealedObject(ctx context.Context, oid uuid.UUID) error {
	log.Ctx(ctx).Debug().Msg("deleting stored object")
	return d.ioProvider.Delete(ctx, oid.Bytes(), io.DataTypeSealedObject)
}

// putSealedAccess encodes a sealed access and sends it to the IO Provider, either as a "Put" or an
// "Update".
func (d *D1) putSealedAccess(ctx context.Context, access *data.SealedAccess, update bool) error {
	accessBytes, err := json.Marshal(access)
	if err != nil {
		return err
	}

	if update {
		log.Ctx(ctx).Debug().Msg("updating stored access")
		err := d.ioProvider.Update(ctx, access.OID.Bytes(), io.DataTypeSealedAccess, accessBytes)
		if errors.Is(err, io.ErrNotFound) {
			return ErrAccessNotFound
		}
		return err
	}

	log.Ctx(ctx).Debug().Msg("storing new access")
	err = d.ioProvider.Put(ctx, access.OID.Bytes(), io.DataTypeSealedAccess, accessBytes)
	if errors.Is(err, io.ErrAlreadyExists) {
		return ErrAccessAlreadyExists
	}
	return err
}

// getSealedAccess fetches bytes from the IO Provider and decodes them into a sealed access.
func (d *D1) getSealedAccess(ctx context.Context, oid uuid.UUID) (*data.SealedAccess, error) {
	log.Ctx(ctx).Debug().Msg("getting stored access")

	accessBytes, err := d.ioProvider.Get(ctx, oid.Bytes(), io.DataTypeSealedAccess)
	if errors.Is(err, io.ErrNotFound) {
		return nil, ErrAccessNotFound
	}
	if err != nil {
		return nil, err
	}

	access := &data.SealedAccess{}
	if err := json.Unmarshal(accessBytes, access); err != nil {
		return nil, err
	}

	access.OID = oid
	return access, nil
}

// deleteSealedAccess deletes a sealed object from the IO Provider.
func (d *D1) deleteSealedAccess(ctx context.Context, oid uuid.UUID) error {
	log.Ctx(ctx).Debug().Msg("deleting stored access")
	return d.ioProvider.Delete(ctx, oid.Bytes(), io.DataTypeSealedAccess)
}
