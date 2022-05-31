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
	"bytes"
	"encoding/gob"

	"github.com/gofrs/uuid"

	"github.com/cyber-crypt-com/encryptonize-lib/data"
	"github.com/cyber-crypt-com/encryptonize-lib/id"
	"github.com/cyber-crypt-com/encryptonize-lib/io"
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
