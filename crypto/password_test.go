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
	"testing"
)

func TestPasswordHasher(t *testing.T) {
	hasher := NewPasswordHasher()
	password, saltAndHash, err := hasher.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}

	if !hasher.Compare(password, saltAndHash) {
		t.Fatal("Password hash check failed")
	}
}

func TestWrongSalt(t *testing.T) {
	hasher := NewPasswordHasher()
	password, saltAndHash, err := hasher.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}

	saltAndHash[0] = saltAndHash[0] ^ 1
	if hasher.Compare(password, saltAndHash) {
		t.Fatal("Expected password hash check to fail")
	}
}

func TestWrongHash(t *testing.T) {
	hasher := NewPasswordHasher()
	password, saltAndHash, err := hasher.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}

	saltAndHash[saltLength] = saltAndHash[saltLength] ^ 1
	if hasher.Compare(password, saltAndHash) {
		t.Fatal("Expected password hash check to fail")
	}
}
