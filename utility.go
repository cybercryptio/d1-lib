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
	"errors"

	"github.com/gofrs/uuid"

	"github.com/cyber-crypt-com/encryptonize-lib/data"
	"github.com/cyber-crypt-com/encryptonize-lib/io"
)

// authorizeAccess checks whether the authorizing user is allowed to access the provided access
// object. If so, the unsealed access object is returned.
func (e *Encryptonize) authorizeAccess(authorizer *data.SealedUser, sealedAccess *data.SealedAccess) (data.Access, error) {
	plainAccess, err := sealedAccess.Unseal(e.accessCryptor)
	if err != nil {
		return data.Access{}, err
	}

	plainAuthorizer, err := authorizer.Unseal(e.userCryptor)
	if err != nil {
		return data.Access{}, err
	}

	for id := range plainAuthorizer.GetGroups() {
		if plainAccess.ContainsGroups(id) {
			return plainAccess, nil
		}
	}
	return data.Access{}, errors.New("User not authorized")
}

// authorizeGroups checks whether the authorizing user is a member of all provided groups. If so, a
// list of all the group IDs is returned.
func (e *Encryptonize) authorizeGroups(authorizer *data.SealedUser, groups ...*data.SealedGroup) ([]uuid.UUID, error) {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return nil, err
	}

	plainAuthorizer, err := authorizer.Unseal(e.userCryptor)
	if err != nil {
		return nil, err
	}
	if !plainAuthorizer.ContainsGroups(groupIDs...) {
		return nil, errors.New("User not authorized")
	}

	return groupIDs, nil
}

// verifyGroups integrity checks all the provided groups. If they are all authentic, a list of all
// the group IDs is returned.
func (e *Encryptonize) verifyGroups(groups ...*data.SealedGroup) ([]uuid.UUID, error) {
	groupIDs := make([]uuid.UUID, 0, len(groups))
	for _, group := range groups {
		if !group.Verify(e.groupCryptor) {
			return nil, errors.New("Invalid group")
		}
		groupIDs = append(groupIDs, group.ID)
	}
	return groupIDs, nil
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
		return e.ioProvider.Update(object.ID, io.DataTypeSealedObject, objectBuffer.Bytes())
	}
	return e.ioProvider.Put(object.ID, io.DataTypeSealedObject, objectBuffer.Bytes())
}

// getSealedObject fetches bytes from the IO Provider and decodes them into a sealed object.
func (e *Encryptonize) getSealedObject(id uuid.UUID) (*data.SealedObject, error) {
	objectBytes, err := e.ioProvider.Get(id, io.DataTypeSealedObject)
	if err != nil {
		return nil, err
	}

	object := &data.SealedObject{}
	dec := gob.NewDecoder(bytes.NewReader(objectBytes))
	err = dec.Decode(object)
	if err != nil {
		return nil, err
	}

	object.ID = id
	return object, nil
}

// putSealedObject encodes a sealed access and sends it to the IO Provider, either as a "Put" or an
// "Update".
func (e *Encryptonize) putSealedAccess(access *data.SealedAccess, update bool) error {
	var accessBuffer bytes.Buffer
	enc := gob.NewEncoder(&accessBuffer)
	if err := enc.Encode(access); err != nil {
		return err
	}

	if update {
		return e.ioProvider.Update(access.ID, io.DataTypeSealedAccess, accessBuffer.Bytes())
	}
	return e.ioProvider.Put(access.ID, io.DataTypeSealedAccess, accessBuffer.Bytes())
}

// getSealedObject fetches bytes from the IO Provider and decodes them into a sealed access.
func (e *Encryptonize) getSealedAccess(id uuid.UUID) (*data.SealedAccess, error) {
	accessBytes, err := e.ioProvider.Get(id, io.DataTypeSealedAccess)
	if err != nil {
		return nil, err
	}

	access := &data.SealedAccess{}
	dec := gob.NewDecoder(bytes.NewReader(accessBytes))
	err = dec.Decode(access)
	if err != nil {
		return nil, err
	}

	access.ID = id
	return access, nil
}
