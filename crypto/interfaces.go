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

// TaggerInterface provides an API to create a cryptographic tag, i.e. a piece of information used for authenticating data.
type TaggerInterface interface {
	// Tag creates a cryptographic tag of data.
	Tag(data interface{}) (mac []byte, err error)
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
