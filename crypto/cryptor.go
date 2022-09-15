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
	"fmt"

	json "github.com/json-iterator/go"
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
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return nil, nil, err
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	key, err := c.random.GetBytes(EncryptionKeyLength)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := c.aead.Encrypt(plaintextBytes, dataBytes, key)
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

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Need to copy here, as AEADInterface is allowed to modify the array.
	ciphertextCopy := make([]byte, len(ciphertext))
	copy(ciphertextCopy, ciphertext)
	plaintextBytes, err := c.aead.Decrypt(ciphertextCopy, dataBytes, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintextBytes, plaintext)
}
