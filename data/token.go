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

package data

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"time"

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
)

// Validity period of tokens created with Encryptonize.CreateToken.
const TokenValidity = time.Hour

// Token contains arbitrary data along with an expiry time. Note: All fields need to be exported in
// order for gob to serialize them.
type Token struct {
	// Arbitrary plaintext data.
	Plaintext []byte

	// Expiry time at which point the data is no longer valid.
	ExpiryTime time.Time
}

// SealedToken contains encrypted data which has an expiry time.
type SealedToken struct {
	// The tokens expiry time. After this time, it can no longer be decrypted.
	ExpiryTime time.Time

	Ciphertext []byte
	WrappedKey []byte
}

// NewToken creates a new token which contains the provided plaintext and has the given validity
// period.
func NewToken(plaintext []byte, validityPeriod time.Duration) Token {
	expiryTime := time.Now().Add(validityPeriod)
	return Token{plaintext, expiryTime}
}

// Seal encrypts the token.
func (t *Token) Seal(cryptor crypto.CryptorInterface) (SealedToken, error) {
	associatedData, err := t.ExpiryTime.GobEncode()
	if err != nil {
		return SealedToken{}, err
	}

	wrappedKey, ciphertext, err := cryptor.Encrypt(t.Plaintext, associatedData)
	if err != nil {
		return SealedToken{}, err
	}

	sealed := SealedToken{
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
		ExpiryTime: t.ExpiryTime,
	}

	return sealed, nil
}

// Unseal decrypts the sealed token.
func (t *SealedToken) Unseal(cryptor crypto.CryptorInterface) (Token, error) {
	// Note that we check the expiry time *before* it has been authenticated through decryption. In
	// general we should never trust unauthenticated data, but if this value has been manipulated, the
	// decrypt call below will anyway fail.
	if t.ExpiryTime.Before(time.Now()) {
		return Token{}, errors.New("Token expired")
	}

	associatedData, err := t.ExpiryTime.GobEncode()
	if err != nil {
		return Token{}, err
	}

	plaintext := []byte{}
	err = cryptor.Decrypt(&plaintext, associatedData, t.WrappedKey, t.Ciphertext)
	if err != nil {
		return Token{}, err
	}

	return Token{plaintext, t.ExpiryTime}, nil
}

// String serializes the sealed token into a raw base 64 URL encoded format.
func (t *SealedToken) String() (string, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(t); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// TokenFromString takes a raw base 64 URL encoded token and deserializes it.
func TokenFromString(tokenString string) (SealedToken, error) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return SealedToken{}, err
	}
	var token SealedToken
	dec := gob.NewDecoder(bytes.NewReader(tokenBytes))
	if err := dec.Decode(&token); err != nil {
		return SealedToken{}, err
	}
	return token, nil
}
