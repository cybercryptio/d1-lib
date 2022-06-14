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
