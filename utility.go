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
	"bytes"
	"context"
	"encoding/gob"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/data"
	"github.com/cybercryptio/d1-lib/id"
	"github.com/cybercryptio/d1-lib/io"
)

// authorizeAccess checks whether the authorizing Identity is allowed to access the provided access
// object. If so, the unsealed access object is returned.
//
// An Identity is authorized to access an object if at least one of the following is true:
//   - The the Identity's ID is part of the Access and the Identity's scope contains the
//     required scope.
//   - One of the Identity's group IDs is part of the Access and that group's scope contains the required
//     scope.
func (d *D1) authorizeAccess(identity *id.Identity, scopes id.Scope, sealedAccess *data.SealedAccess) (data.Access, error) {
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
	var objectBuffer bytes.Buffer
	enc := gob.NewEncoder(&objectBuffer)
	if err := enc.Encode(object); err != nil {
		return err
	}

	if update {
		return d.ioProvider.Update(ctx, object.OID.Bytes(), io.DataTypeSealedObject, objectBuffer.Bytes())
	}
	return d.ioProvider.Put(ctx, object.OID.Bytes(), io.DataTypeSealedObject, objectBuffer.Bytes())
}

// getSealedObject fetches bytes from the IO Provider and decodes them into a sealed object.
func (d *D1) getSealedObject(ctx context.Context, oid uuid.UUID) (*data.SealedObject, error) {
	objectBytes, err := d.ioProvider.Get(ctx, oid.Bytes(), io.DataTypeSealedObject)
	if err != nil {
		return nil, err
	}

	object := &data.SealedObject{}
	dec := gob.NewDecoder(bytes.NewReader(objectBytes))
	err = dec.Decode(object)
	if err != nil {
		return nil, err
	}

	object.OID = oid
	return object, nil
}

// deleteSealedObject deletes a sealed object from the IO Provider.
func (d *D1) deleteSealedObject(ctx context.Context, oid uuid.UUID) error {
	return d.ioProvider.Delete(ctx, oid.Bytes(), io.DataTypeSealedObject)
}

// putSealedAccess encodes a sealed access and sends it to the IO Provider, either as a "Put" or an
// "Update".
func (d *D1) putSealedAccess(ctx context.Context, access *data.SealedAccess, update bool) error {
	var accessBuffer bytes.Buffer
	enc := gob.NewEncoder(&accessBuffer)
	if err := enc.Encode(access); err != nil {
		return err
	}

	if update {
		return d.ioProvider.Update(ctx, access.OID.Bytes(), io.DataTypeSealedAccess, accessBuffer.Bytes())
	}
	return d.ioProvider.Put(ctx, access.OID.Bytes(), io.DataTypeSealedAccess, accessBuffer.Bytes())
}

// getSealedAccess fetches bytes from the IO Provider and decodes them into a sealed access.
func (d *D1) getSealedAccess(ctx context.Context, oid uuid.UUID) (*data.SealedAccess, error) {
	accessBytes, err := d.ioProvider.Get(ctx, oid.Bytes(), io.DataTypeSealedAccess)
	if err != nil {
		return nil, err
	}

	access := &data.SealedAccess{}
	dec := gob.NewDecoder(bytes.NewReader(accessBytes))
	err = dec.Decode(access)
	if err != nil {
		return nil, err
	}

	access.OID = oid
	return access, nil
}

// deleteSealedAccess deletes a sealed object from the IO Provider.
func (d *D1) deleteSealedAccess(ctx context.Context, oid uuid.UUID) error {
	return d.ioProvider.Delete(ctx, oid.Bytes(), io.DataTypeSealedAccess)
}
