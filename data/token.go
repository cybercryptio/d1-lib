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

package data

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/cybercryptio/d1-lib/v2/crypto"
	json "github.com/json-iterator/go"
)

// Validity period of tokens created with D1.CreateToken.
const TokenValidity = time.Hour

// Token contains arbitrary data along with an expiry time. Note: All fields need to be exported in
// order to serialize them.
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
	associatedData, err := t.ExpiryTime.MarshalBinary()
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

	associatedData, err := t.ExpiryTime.MarshalBinary()
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
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TokenFromString takes a raw base 64 URL encoded token and deserializes it.
func TokenFromString(tokenString string) (SealedToken, error) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return SealedToken{}, err
	}
	var token SealedToken
	if err := json.Unmarshal(tokenBytes, &token); err != nil {
		return SealedToken{}, err
	}
	return token, nil
}
