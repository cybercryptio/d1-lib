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
	"bytes"
	"testing"
)

func TestCryptor(t *testing.T) {
	rand := &NativeRandom{}
	KEK, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	cryptor, err := NewAESCryptor(KEK)
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	for i := uint(0); i < 65; i++ {
		for j := uint(0); j < 65; j++ {
			data, err := rand.GetBytes(i)
			if err != nil {
				t.Fatalf("Random failed: %v", err)
			}

			aad, err := rand.GetBytes(j)
			if err != nil {
				t.Fatalf("Random failed: %v", err)
			}

			wrappedKey, ciphertext, err := cryptor.Encrypt(data, aad)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			var plaintext []byte
			err = cryptor.Decrypt(&plaintext, aad, wrappedKey, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(data, plaintext) {
				t.Fatalf("plaintext doesn't match %x != %x", data, plaintext)
			}
		}
	}
}

func TestCryptorIdempotent(t *testing.T) {
	rand := &NativeRandom{}
	KEK, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	cryptor, err := NewAESCryptor(KEK)
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	data, err := rand.GetBytes(1024)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	aad, err := rand.GetBytes(1024)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	aadCopy := make([]byte, len(aad))
	copy(aadCopy, aad)

	wrappedKey, ciphertext, err := cryptor.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	ciphertextCopy := make([]byte, len(ciphertext))
	copy(ciphertextCopy, ciphertext)
	wrappedKeyCopy := make([]byte, len(wrappedKey))
	copy(wrappedKeyCopy, wrappedKey)

	var plaintext []byte
	err = cryptor.Decrypt(&plaintext, aad, wrappedKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(data, dataCopy) {
		t.Fatalf("'data' was changed during operation")
	}
	if !bytes.Equal(aad, aadCopy) {
		t.Fatalf("'aad' was changed during operation")
	}
	if !bytes.Equal(ciphertext, ciphertextCopy) {
		t.Fatalf("'ciphertext' was changed during operation")
	}
	if !bytes.Equal(wrappedKey, wrappedKeyCopy) {
		t.Fatalf("'wrappedKey' was changed during operation")
	}
}
