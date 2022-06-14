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

package crypto

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

const EncryptionKeyLength = 32
const WrapperKeyLength = 32

var ErrInvalidKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", WrapperKeyLength)

// Cryptor implements the CryptorInterface.
type Cryptor struct {
	random     RandomInterface
	keyWrapper KeyWrapperInterface
	aead       AEADInterface
}

// NewAESCryptor creates a Cryptor which uses AES-256 in GCM mode.
func NewAESCryptor(KEK []byte) (Cryptor, error) {
	if len(KEK) != WrapperKeyLength {
		return Cryptor{}, ErrInvalidKeyLength
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

	key, err := c.random.GetBytes(EncryptionKeyLength)
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
