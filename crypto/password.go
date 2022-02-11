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
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

// GenerateUserPassword generates a random base64 encoded password and a salt
func GenerateUserPassword() (string, []byte, error) {
	password, err := Random(32)
	if err != nil {
		return "", nil, err
	}

	salt, err := Random(8)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(password), salt, nil
}

// HashPassword hashes a password according to
// https://pages.nist.gov/800-63-3/sp800-63b.html#-5112-memorized-secret-verifiers
func HashPassword(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 10000, 32, sha3.New256)
}

// CompareHashAndPassword returns true if hash and password are equal
func CompareHashAndPassword(password string, hash []byte, salt []byte) bool {
	return subtle.ConstantTimeCompare(HashPassword(password, salt), hash) == 1
}
