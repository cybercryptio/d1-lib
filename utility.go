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

package encryptonize

import (
	"bytes"
	"encoding/gob"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/data"
	"github.com/cybercryptio/d1-lib/id"
	"github.com/cybercryptio/d1-lib/io"
)

// authorizeAccess checks whether the authorizing user is allowed to access the provided access
// object. If so, the unsealed access object is returned.
//
// A user is authorized to access an object if at least one of the following is true:
// * The the user's identity ID is part of the Access and the user's identity scope contains the
//   required scope.
// * One of the user's group IDs is part of the Access and that group's scope contains the required
//   scope.
func (e *Encryptonize) authorizeAccess(identity *id.Identity, scopes id.Scope, sealedAccess *data.SealedAccess) (data.Access, error) {
	plainAccess, err := sealedAccess.Unseal(e.accessCryptor)
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
func (e *Encryptonize) putSealedObject(object *data.SealedObject, update bool) error {
	var objectBuffer bytes.Buffer
	enc := gob.NewEncoder(&objectBuffer)
	if err := enc.Encode(object); err != nil {
		return err
	}

	if update {
		return e.ioProvider.Update(object.OID, io.DataTypeSealedObject, objectBuffer.Bytes())
	}
	return e.ioProvider.Put(object.OID, io.DataTypeSealedObject, objectBuffer.Bytes())
}

// getSealedObject fetches bytes from the IO Provider and decodes them into a sealed object.
func (e *Encryptonize) getSealedObject(oid uuid.UUID) (*data.SealedObject, error) {
	objectBytes, err := e.ioProvider.Get(oid, io.DataTypeSealedObject)
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
func (e *Encryptonize) deleteSealedObject(oid uuid.UUID) error {
	err := e.ioProvider.Delete(oid, io.DataTypeSealedObject)
	return err
}

// putSealedAccess encodes a sealed access and sends it to the IO Provider, either as a "Put" or an
// "Update".
func (e *Encryptonize) putSealedAccess(access *data.SealedAccess, update bool) error {
	var accessBuffer bytes.Buffer
	enc := gob.NewEncoder(&accessBuffer)
	if err := enc.Encode(access); err != nil {
		return err
	}

	if update {
		return e.ioProvider.Update(access.OID, io.DataTypeSealedAccess, accessBuffer.Bytes())
	}
	return e.ioProvider.Put(access.OID, io.DataTypeSealedAccess, accessBuffer.Bytes())
}

// getSealedAccess fetches bytes from the IO Provider and decodes them into a sealed access.
func (e *Encryptonize) getSealedAccess(oid uuid.UUID) (*data.SealedAccess, error) {
	accessBytes, err := e.ioProvider.Get(oid, io.DataTypeSealedAccess)
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
func (e *Encryptonize) deleteSealedAccess(oid uuid.UUID) error {
	err := e.ioProvider.Delete(oid, io.DataTypeSealedAccess)
	return err
}
