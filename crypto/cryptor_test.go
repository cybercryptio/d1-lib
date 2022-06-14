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
