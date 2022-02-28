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
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const passwordLength = 32
const saltLength = 8
const hashLength = 32
const iterationCount = 10000

// PasswordHasher implements PasswordHasherInterface using bpkdf2.
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
