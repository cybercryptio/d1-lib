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
	"encoding/hex"
	"testing"
)

// NIST test case
var oek, _ = hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
var nonce, _ = hex.DecodeString("cafebabefacedbaddecaf888")
var aad, _ = hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
var plaintext, _ = hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
var ciphertextHex = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b" + hex.EncodeToString(nonce)

func TestAES256GCMEncryptDecrypt(t *testing.T) {
	crypter := &AES256GCM{&MockRandom{nonce}}
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

func TestAES256GCMWrongTag(t *testing.T) {
	crypter := &AES256GCM{&NativeRandom{}}
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

func TestAES256GCMAssociatedDataSizes(t *testing.T) {
	rand := &NativeRandom{}
	crypter := &AES256GCM{rand}

	encryptDecrypt := func(sz uint) bool {
		aad, _ := rand.GetBytes(sz)
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
	var sz uint
	for sz = 0; sz < 4096; sz++ {
		if !encryptDecrypt(sz) {
			t.Errorf("error encrypting and decrypting with AD of size %d", sz)
		}
	}
}

func TestAES256GCMPlaintextSizes(t *testing.T) {
	rand := &NativeRandom{}
	crypter := &AES256GCM{rand}

	encryptDecrypt := func(sz uint) bool {
		plaintext, _ := rand.GetBytes(sz)
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
	var sz uint
	for sz = 0; sz < 4096; sz++ {
		if !encryptDecrypt(sz) {
			t.Errorf("error encrypting and decrypting with plaintext of size %d", sz)
		}
	}
}
