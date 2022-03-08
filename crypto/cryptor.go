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

package crypto

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

const encryptionKeyLength = 32
const wrapperKeyLength = 32

var errInvalidKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", wrapperKeyLength)

// Cryptor implements the CryptorInterface.
type Cryptor struct {
	random     RandomInterface
	keyWrapper KeyWrapperInterface
	aead       AEADInterface
}

// NewAESCryptor creates a Cryptor which uses AES-256 in GCM mode.
func NewAESCryptor(KEK []byte) (Cryptor, error) {
	if len(KEK) != wrapperKeyLength {
		return Cryptor{}, errInvalidKeyLength
	}

	keyWrapper, err := NewKWP(KEK)
	if err != nil {
		return Cryptor{}, err
	}

	return Cryptor{
		random:     &NativeRandom{},
		keyWrapper: keyWrapper,
		aead:       &AES256GCM{&NativeRandom{}},
	}, nil
}

func (c *Cryptor) Encrypt(plaintext, data interface{}) ([]byte, []byte, error) {
	var plaintextBuffer bytes.Buffer
	enc := gob.NewEncoder(&plaintextBuffer)
	if err := enc.Encode(plaintext); err != nil {
		return nil, nil, err
	}

	var dataBuffer bytes.Buffer
	enc = gob.NewEncoder(&dataBuffer)
	if err := enc.Encode(data); err != nil {
		return nil, nil, err
	}

	key, err := c.random.GetBytes(encryptionKeyLength)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := c.aead.Encrypt(plaintextBuffer.Bytes(), dataBuffer.Bytes(), key)
	if err != nil {
		return nil, nil, err
	}

	wrappedKey, err := c.keyWrapper.Wrap(key)
	if err != nil {
		return nil, nil, err
	}

	return wrappedKey, ciphertext, nil
}

func (c *Cryptor) Decrypt(plaintext, data interface{}, wrappedKey, ciphertext []byte) error {
	key, err := c.keyWrapper.Unwrap(wrappedKey)
	if err != nil {
		return err
	}

	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(data); err != nil {
		return err
	}
	dataBytes := buffer.Bytes()

	// Need to copy here, as AEADInterface is allowed to modify the array.
	ciphertextCopy := make([]byte, len(ciphertext))
	copy(ciphertextCopy, ciphertext)
	plaintextBytes, err := c.aead.Decrypt(ciphertextCopy, dataBytes, key)
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(bytes.NewReader(plaintextBytes))
	return dec.Decode(plaintext)
}
