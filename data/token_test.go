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
	"time"

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
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

	if !sealed.verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if sealed.verify(&cryptor) {
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

	if !sealed.verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.ExpiryTime = sealed.ExpiryTime.Add(time.Hour)
	if sealed.verify(&cryptor) {
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
	if sealed.verify(&cryptor) {
		t.Fatal("Expected verification to fail")
	}
}
