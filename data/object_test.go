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

var id = uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000")

func TestObjectSeal(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	object := Object{[]byte("plaintext"), []byte("data")}
	wrappedKey, sealed, err := object.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	unsealed, err := sealed.Unseal(wrappedKey, &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(object, unsealed) {
		t.Fatal("Unsealed object not equal to original")
	}
}

func TestObjectVerifyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	object := Object{[]byte("plaintext"), []byte("data")}
	wrappedKey, sealed, err := object.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(wrappedKey, &cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if _, err := sealed.Unseal(wrappedKey, &cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}

func TestObjectVerifyData(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	object := Object{[]byte("plaintext"), []byte("data")}
	wrappedKey, sealed, err := object.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(wrappedKey, &cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.AssociatedData[0] = sealed.AssociatedData[0] ^ 1
	if _, err := sealed.Unseal(wrappedKey, &cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}

func TestObjectVerifyID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	object := Object{[]byte("plaintext"), []byte("data")}
	wrappedKey, sealed, err := object.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(wrappedKey, &cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.OID = uuid.Must(uuid.NewV4())
	if _, err := sealed.Unseal(wrappedKey, &cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}

func TestObjectID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	object := Object{[]byte("plaintext"), []byte("data")}
	_, sealed, err := object.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.OID != id {
		t.Fatalf("Object ID not equal to expected value: %s != %s", sealed.OID, id)
	}
}
