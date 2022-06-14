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
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const passwordLength = 32
const saltLength = 8
const hashLength = 32
const iterationCount = 10000

// PasswordHasher implements PasswordHasherInterface using pbkdf2.
type PasswordHasher struct {
	random RandomInterface
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{&NativeRandom{}}
}

func (p *PasswordHasher) GeneratePassword() (string, []byte, error) {
	passwordBytes, err := p.random.GetBytes(passwordLength)
	if err != nil {
		return "", nil, err
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)

	salt, err := p.random.GetBytes(saltLength)
	if err != nil {
		return "", nil, err
	}

	hash := pbkdf2.Key([]byte(password), salt, iterationCount, hashLength, sha3.New256)
	saltAndHash := append(salt, hash...)

	return password, saltAndHash, nil
}

func (p *PasswordHasher) Compare(password string, saltAndHash []byte) bool {
	salt := saltAndHash[:saltLength]
	hash := saltAndHash[saltLength:]
	return subtle.ConstantTimeCompare(passwordHash([]byte(password), salt), hash) == 1
}

func passwordHash(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterationCount, hashLength, sha3.New256)
}
