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

// CryptorInterface offers an API to encrypt / decrypt data and additional associated data with a (wrapped) random key
type CryptorInterface interface {
	// Encrypt encrypts data + aad with a random key and return the wrapped key and the ciphertext
	Encrypt(data, aad []byte) (wrappedKey, ciphertext []byte, err error)

	// EncryptWithKey encrypts data + aad with a wrapped key and returns the ciphertext
	EncryptWithKey(data, aad, key []byte) (ciphertext []byte, err error)

	// EncodeAndEncrypt serializes the data, but otherwise behaves like `Encrypt`
	EncodeAndEncrypt(data interface{}, aad []byte) (wrappedKey, ciphertext []byte, err error)

	// Decrypt decrypts a ciphertext + aad with a wrapped key
	Decrypt(wrappedKey, ciphertext, aad []byte) (plaintext []byte, err error)

	// DecodeAndDecrypt behaves like `Decrypt` by deserializes the result into `data`
	DecodeAndDecrypt(data interface{}, wrappedKey, ciphertext, aad []byte) (err error)
}

// KeyWrapperInterface offers an API to wrap / unwrap key material
type KeyWrapperInterface interface {
	//Wrap wraps the provided key material.
	Wrap(data []byte) ([]byte, error)

	// Unwrap unwraps a wrapped key.
	Unwrap(data []byte) ([]byte, error)
}
