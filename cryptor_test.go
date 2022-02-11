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
package encryptonize

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"encryptonize/crypto"
)

func TestAESCrypter(t *testing.T) {
	KEK, err := crypto.Random(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	crypter, err := NewAESCryptor(KEK)
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	for i := 0; i < 65; i++ {
		for j := 0; j < 65; j++ {
			data, err := crypto.Random(i)
			if err != nil {
				t.Fatalf("Random failed: %v", err)
			}

			aad, err := crypto.Random(j)
			if err != nil {
				t.Fatalf("Random failed: %v", err)
			}

			wrappedKey, ciphertext, err := crypter.Encrypt(data, aad)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			plaintext, err := crypter.Decrypt(wrappedKey, ciphertext, aad)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(data, plaintext) {
				t.Fatalf("plaintext doesn't match %x != %x", data, plaintext)
			}
		}
	}
}

func TestAESCrypterEncryptWrap(t *testing.T) {
	KEK, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	expectedWrappedKey, _ := hex.DecodeString("4a8029243027353b0694cf1bd8fc745bb0ce8a739b19b1960b12426d4c39cfeda926d103ab34e9f6")

	tmpReader := rand.Reader
	defer func() { rand.Reader = tmpReader }()
	rand.Reader = bytes.NewReader(append(key, make([]byte, 64)...))

	crypter, err := NewAESCryptor(KEK)
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	wrappedKey, _, err := crypter.Encrypt(make([]byte, 16), make([]byte, 16))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !bytes.Equal(expectedWrappedKey, wrappedKey) {
		t.Fatalf("wrappedKey doesn't match %x != %x", expectedWrappedKey, wrappedKey)
	}
}

func TestAESCrypterEncryption(t *testing.T) {
	KEK := make([]byte, 32)
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	expectedPlaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	expectedCipherText, _ := hex.DecodeString("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b" + "cafebabefacedbaddecaf888")

	tmpReader := rand.Reader
	defer func() { rand.Reader = tmpReader }()
	rand.Reader = bytes.NewReader(append(key, nonce...))

	crypter, err := NewAESCryptor(KEK)
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	wrappedKey, ciphertext, err := crypter.Encrypt(expectedPlaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !bytes.Equal(expectedCipherText, ciphertext) {
		t.Fatalf("ciphertext doesn't match:\n%x\n!=\n%x", expectedCipherText, ciphertext)
	}

	plaintext, err := crypter.Decrypt(wrappedKey, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(expectedPlaintext, plaintext) {
		t.Fatalf("ciphertext doesn't match:\n%x\n!=\n%x", expectedPlaintext, plaintext)
	}
}

func TestAESCrypterEncryptWithKey(t *testing.T) {
	KEK := make([]byte, 32)
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	expectedPlaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	expectedCipherText, _ := hex.DecodeString("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b" + "cafebabefacedbaddecaf888")

	tmpReader := rand.Reader
	defer func() { rand.Reader = tmpReader }()
	rand.Reader = bytes.NewReader(nonce)

	crypter, err := NewAESCryptor(KEK)
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	wrappedKey, err := crypter.keyWrap.Wrap(key)
	if err != nil {
		t.Fatalf("Failed to wrap a key: %v", err)
	}

	ciphertext, err := crypter.EncryptWithKey(expectedPlaintext, aad, wrappedKey)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}

	if !bytes.Equal(expectedCipherText, ciphertext) {
		t.Fatalf("ciphertext doesn't match:\n%x\n!=\n%x", expectedCipherText, ciphertext)
	}

	plaintext, err := crypter.Decrypt(wrappedKey, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(expectedPlaintext, plaintext) {
		t.Fatalf("ciphertext doesn't match:\n%x\n!=\n%x", expectedPlaintext, plaintext)
	}
}

func TestAESCrypterInvalidLength(t *testing.T) {
	KEK := make([]byte, 32)
	// AES expects 16, 24, 32
	// we only accept 32
	invalidLengthKey := "not32bytesbutmorethan16!"
	plaintext, _ := hex.DecodeString("d93132")
	aad, _ := hex.DecodeString("deadbeef")

	crypter, err := NewAESCryptor(KEK)
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	kwp, err := crypto.NewKWP(KEK)
	if err != nil {
		t.Fatalf("NewKWP failed: %v", err)
	}

	wrappedKey, err := kwp.Wrap([]byte(invalidLengthKey))
	if err != nil {
		t.Fatalf("Failed wrapping key: %v", err)
	}

	_, err = crypter.EncryptWithKey(plaintext, aad, wrappedKey)
	if err == nil {
		t.Fatalf("Expected EncryptWithKey to fail due to invalid key length")
	}
}
