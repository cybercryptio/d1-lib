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
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type AESCrypter struct {
}

const nonceLength = 12
const tagLength = 16

const Overhead = int(tagLength + nonceLength)

// Encrypt encrypts a plaintext with additional associated data (aad) using the provided key returning the resulting ciphertext.
// The backing array of plaintext is likely modified during this operation.
func (c *AESCrypter) Encrypt(plaintext, aad, key []byte) ([]byte, error) {
	ciphertext := append(plaintext, make([]byte, Overhead)...) // make sure we also have space
	nonce, err := Random(nonceLength)
	if err != nil {
		return nil, err
	}
	copy(ciphertext[len(plaintext)+tagLength:], nonce)

	data := ciphertext[:len(plaintext)]
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return nil, err
	}

	aesgcm.Seal(data[:0], nonce, data, aad)

	return ciphertext, nil
}

// Decrypt decrypts a ciphertext with additional associated data (aad) using the provided key returning the resulting plaintext.
// ciphertext is modified during this operation.
func (c *AESCrypter) Decrypt(ciphertext, aad, key []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	data := ciphertext[:len(ciphertext)-nonceLength]
	nonce := ciphertext[len(ciphertext)-nonceLength:]
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return nil, err
	}

	_, err = aesgcm.Open(data[:0], nonce, data, aad)
	if err != nil {
		return nil, err
	}

	return ciphertext[:len(ciphertext)-Overhead], err
}
