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
	"time"

	"github.com/cybercryptio/d1-lib/crypto"
)

func TestTokenSeal(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	token := NewToken([]byte("plaintext"), time.Minute)
	sealed, err := token.Seal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}

	unsealed, err := sealed.Unseal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(token, unsealed) {
		t.Fatal("Unsealed token not equal to original")
	}
}

func TestTokenVerifyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	token := NewToken([]byte("plaintext"), time.Minute)
	sealed, err := token.Seal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(&cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if _, err := sealed.Unseal(&cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}

func TestTokenVerifyExpiry(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	token := NewToken([]byte("plaintext"), time.Minute)
	sealed, err := token.Seal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(&cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.ExpiryTime = sealed.ExpiryTime.Add(time.Hour)
	if _, err := sealed.Unseal(&cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}

func TestTokenExpired(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	token := NewToken([]byte("plaintext"), -time.Minute)
	sealed, err := token.Seal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sealed.Unseal(&cryptor)
	if err == nil {
		t.Fatal("Expected unseal to fail")
	}
}
