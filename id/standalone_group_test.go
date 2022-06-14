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

package id

import (
	"testing"

	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

func TestGroupSeal(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	group := newGroup(ScopeEncrypt)
	sealed, err := group.seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	unsealed, err := sealed.unseal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(group, unsealed) {
		t.Fatal("Unsealed object not equal to original")
	}
}

func TestGroupVerifyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	group := newGroup(ScopeEncrypt)
	sealed, err := group.seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if !sealed.verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if sealed.verify(&cryptor) {
		t.Fatal("Verification should have failed")
	}
}

func TestGroupVerifyID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	group := newGroup(ScopeEncrypt)
	sealed, err := group.seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if !sealed.verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.GID = uuid.Must(uuid.NewV4())
	if sealed.verify(&cryptor) {
		t.Fatal("Verification should have failed")
	}
}

func TestGroupID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	group := newGroup(ScopeEncrypt)
	sealed1, err := group.seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	sealed2, err := group.seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if sealed1.GID == sealed2.GID {
		t.Fatal("Expected different IDs")
	}
}
