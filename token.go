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
	"errors"
	"time"

	"encryptonize/crypto"
)

const TokenValidity = time.Hour

type Token struct {
	Plaintext  []byte
	ExpiryTime time.Time
}

type SealedToken struct {
	ciphertext []byte
	wrappedKey []byte
	ExpiryTime time.Time
}

func NewToken(plaintext []byte, validityPeriod time.Duration) Token {
	expiryTime := time.Now().Add(validityPeriod)
	return Token{plaintext, expiryTime}
}

func (t *Token) seal(cryptor crypto.CryptorInterface) (SealedToken, error) {
	associatedData, err := t.ExpiryTime.GobEncode()
	if err != nil {
		return SealedToken{}, err
	}

	wrappedKey, ciphertext, err := cryptor.Encrypt(t.Plaintext, associatedData)
	if err != nil {
		return SealedToken{}, err
	}

	return SealedToken{ciphertext, wrappedKey, t.ExpiryTime}, nil
}

func (t *SealedToken) unseal(cryptor crypto.CryptorInterface) (Token, error) {
	associatedData, err := t.ExpiryTime.GobEncode()
	if err != nil {
		return Token{}, err
	}

	plaintext := []byte{}
	err = cryptor.Decrypt(&plaintext, associatedData, t.wrappedKey, t.ciphertext)
	if err != nil {
		return Token{}, err
	}

	if t.ExpiryTime.Before(time.Now()) {
		return Token{}, errors.New("Token expired")
	}

	return Token{plaintext, t.ExpiryTime}, nil
}

func (t *SealedToken) verify(cryptor crypto.CryptorInterface) bool {
	_, err := t.unseal(cryptor)
	if err != nil {
		return false
	}
	return t.ExpiryTime.After(time.Now())
}
