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
	"testing"

	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
)

func TestGroupSeal(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	group := NewGroup([]byte("data"))
	sealed, err := group.Seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	unsealed, err := sealed.Unseal(&cryptor)
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

	group := NewGroup([]byte("data"))
	sealed, err := group.Seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if !sealed.Verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if sealed.Verify(&cryptor) {
		t.Fatal("Verification should have failed")
	}
}

func TestGroupVerifyID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	group := NewGroup([]byte("data"))
	sealed, err := group.Seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if !sealed.Verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.ID = uuid.Must(uuid.NewV4())
	if sealed.Verify(&cryptor) {
		t.Fatal("Verification should have failed")
	}
}

func TestGroupID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	group := NewGroup([]byte("data"))
	sealed1, err := group.Seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	sealed2, err := group.Seal(uuid.Must(uuid.NewV4()), &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if sealed1.ID == sealed2.ID {
		t.Fatal("Expected different IDs")
	}
}
