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
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// NIST test case
var oek, _ = hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
var nonce, _ = hex.DecodeString("cafebabefacedbaddecaf888")
var aad, _ = hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
var plaintext, _ = hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
var ciphertextHex = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b" + hex.EncodeToString(nonce)

func TestEncryptDecrypt(t *testing.T) {
	crypter := &AESCrypter{}

	tmpReader := rand.Reader
	defer func() { rand.Reader = tmpReader }()
	rand.Reader = bytes.NewReader(nonce)

	plaintext := append([]byte(nil), plaintext...)

	ciphertext, err := crypter.Encrypt(plaintext, aad, oek)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if ciphertextHex != hex.EncodeToString(ciphertext) {
		t.Fatalf("ciphertext doesn't match:\n%s\n%s\n", ciphertextHex, hex.EncodeToString(ciphertext))
	}

	gotPlaintext, err := crypter.Decrypt(ciphertext, aad, oek)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, gotPlaintext) {
		t.Fatalf("plaintext doesn't match:\n%x\n%x\n", plaintext, gotPlaintext)
	}
}

func TestWrongTag(t *testing.T) {
	crypter := &AESCrypter{}
	plaintext := append([]byte(nil), plaintext...)
	ciphertext, err := crypter.Encrypt(plaintext, aad, oek)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Change a bit in the ciphertext
	ciphertext[0] ^= 1

	_, err = crypter.Decrypt(ciphertext, aad, oek)
	if err == nil {
		t.Fatalf("Decryption of modified ciphertext should have failed")
	}
}

func TestAssociatedDataSizes(t *testing.T) {
	crypter := &AESCrypter{}

	encryptDecrypt := func(sz uint32) bool {
		aad := GetRandomBytes(sz)
		ciphertext, err := crypter.Encrypt(plaintext, aad, oek)

		if err != nil {
			return false
		}

		gotPlaintext, err := crypter.Decrypt(ciphertext, aad, oek)

		if err != nil {
			return false
		}

		return bytes.Equal(plaintext, gotPlaintext)
	}

	// test the fixed sizes
	var sz uint32
	for sz = 0; sz < 4096; sz++ {
		if !encryptDecrypt(sz) {
			t.Errorf("error encrypting and decrypting with AD of size %d", sz)
		}
	}
}

func TestPlaintextSizes(t *testing.T) {
	crypter := &AESCrypter{}

	encryptDecrypt := func(sz uint32) bool {
		plaintext := GetRandomBytes(sz)
		ciphertext, err := crypter.Encrypt(plaintext, aad, oek)

		if err != nil {
			return false
		}

		// check if the ciphertext is equal to the plaintext
		// for very short plaintexts this check could fail by chance because of the
		// pseudorandom nature of encryption (e.g.: size 1 -- probability: 1/256)
		if sz >= 16 && bytes.Equal(plaintext, ciphertext[:len(plaintext)]) {
			t.Errorf("ciphertext matches plaintext for plaintext: %s", hex.EncodeToString(plaintext))
		}

		gotPlaintext, err := crypter.Decrypt(ciphertext, aad, oek)

		if err != nil {
			return false
		}

		return bytes.Equal(plaintext, gotPlaintext)
	}

	// test the fixed sizes
	var sz uint32
	for sz = 0; sz < 4096; sz++ {
		if !encryptDecrypt(sz) {
			t.Errorf("error encrypting and decrypting with plaintext of size %d", sz)
		}
	}
}
