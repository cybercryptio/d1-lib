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

// CryptorInterface provides an API to encrypt/decrypt data and additional associated data with a
// (wrapped) random key.
type CryptorInterface interface {
	// Encrypt encrypts plaintext and associated data with a random key. It returns the wrapped key
	// and the ciphertext.
	Encrypt(plaintext, data interface{}) (wrappedKey, ciphertext []byte, err error)

	// Decrypt decrypts a ciphertext using the provided wrapped key and associated data. It
	// deserializes the result into `plaintext`.
	Decrypt(plaintext, data interface{}, wrappedKey, ciphertext []byte) (err error)
}

// KeyWrapperInterface provides an API to wrap/unwrap key material.
type KeyWrapperInterface interface {
	// Wrap wraps the provided key material.
	Wrap(key []byte) ([]byte, error)

	// Unwrap unwraps a wrapped key.
	Unwrap(key []byte) ([]byte, error)
}

// AEADInterface represents an Authenticated Encryption scheme with Associated Data.
type AEADInterface interface {
	// Encrypt encrypts uses the key to encrypt and authenticate the plaintext and authenticated the
	// associated data. The backing array of `plaintext` is likely modified during this operation.
	Encrypt(plaintext, data, key []byte) ([]byte, error)

	// Decrypt uses the key to verify the authenticity of the ciphertext and associated data and
	// decrypt the ciphertext. The `ciphertext` array is modified during this operation.
	Decrypt(ciphertext, data, key []byte) ([]byte, error)
}

// RandomInterface provides an API for getting cryptographically secure random bytes.
type RandomInterface interface {
	// GetBytes generates the requested number of random bytes.
	GetBytes(n uint) ([]byte, error)
}

// PasswordHasherInterface provides an API for securely generating and checking passwords.
type PasswordHasherInterface interface {
	// GeneratePassword returns a random password and a salted hash of that password.
	GeneratePassword() (string, []byte, error)

	// Compare checks if the password matches the given hash.
	Compare(password string, saltAndHash []byte) bool
}
