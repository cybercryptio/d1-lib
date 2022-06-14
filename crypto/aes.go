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
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AES256GCM implements AEADInterface.
type AES256GCM struct {
	Random RandomInterface
}

const keyLength = 32
const nonceLength = 12
const tagLength = 16
const Overhead = int(tagLength + nonceLength)

func (a *AES256GCM) Encrypt(plaintext, aad, key []byte) ([]byte, error) {
	if len(key) != keyLength {
		return nil, errors.New("invalid key length")
	}

	ciphertext := append(plaintext, make([]byte, Overhead)...) // make sure we also have space
	nonce, err := a.Random.GetBytes(nonceLength)
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

func (a *AES256GCM) Decrypt(ciphertext, aad, key []byte) ([]byte, error) {
	if len(key) != keyLength {
		return nil, errors.New("invalid key length")
	}
	if len(ciphertext) < Overhead {
		return nil, errors.New("invalid ciphertext length")
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
