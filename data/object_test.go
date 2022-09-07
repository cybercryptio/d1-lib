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
	"testing"

	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/v2/crypto"
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
