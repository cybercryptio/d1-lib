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
	"github.com/gofrs/uuid"

	"encryptonize/crypto"
)

type Object struct {
	Plaintext      []byte
	AssociatedData []byte
}

type SealedObject struct {
	ciphertext     []byte
	AssociatedData []byte
	ID             uuid.UUID
}

func (o *Object) seal(cryptor crypto.CryptorInterface) ([]byte, SealedObject, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, SealedObject{}, err
	}

	associatedData := make([]byte, 0, uuid.Size+len(o.AssociatedData))
	associatedData = append(associatedData, id.Bytes()...)
	associatedData = append(associatedData, o.AssociatedData...)

	wrappedKey, ciphertext, err := cryptor.Encrypt(o.Plaintext, associatedData)
	if err != nil {
		return nil, SealedObject{}, err
	}

	return wrappedKey, SealedObject{ciphertext, o.AssociatedData, id}, nil
}

func (o *SealedObject) unseal(wrappedKey []byte, cryptor crypto.CryptorInterface) (Object, error) {
	associatedData := make([]byte, 0, uuid.Size+len(o.AssociatedData))
	associatedData = append(associatedData, o.ID.Bytes()...)
	associatedData = append(associatedData, o.AssociatedData...)

	plaintext := []byte{}
	err := cryptor.Decrypt(&plaintext, associatedData, wrappedKey, o.ciphertext)
	if err != nil {
		return Object{}, err
	}

	return Object{plaintext, o.AssociatedData}, nil
}

func (o *SealedObject) verify(wrappedKey []byte, cryptor crypto.CryptorInterface) bool {
	_, err := o.unseal(wrappedKey, cryptor)
	return err == nil
}
