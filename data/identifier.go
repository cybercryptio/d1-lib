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
	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

// Identifier contains an identifier (e.g. a document ID) and the counter used to compute the next sealed Identifier.
type Identifier struct {
	Identifier  string
	NextCounter uint64
}

// SealedIdentifier is an encrypted structure which defines an occurrence of a specific keyword in a specific identifier.
type SealedIdentifier struct {
	Ciphertext []byte
	WrappedKey []byte
}

// Seal encrypts the plaintext Identifier.
func (i *Identifier) Seal(label uuid.UUID, cryptor crypto.CryptorInterface) (SealedIdentifier, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(i, label)
	if err != nil {
		return SealedIdentifier{}, err
	}

	return SealedIdentifier{
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
	}, nil
}

// Unseal decrypts the sealed Identifier.
func (i *SealedIdentifier) Unseal(label uuid.UUID, cryptor crypto.CryptorInterface) (Identifier, error) {
	plainID := Identifier{}
	if err := cryptor.Decrypt(&plainID, label, i.WrappedKey, i.Ciphertext); err != nil {
		return Identifier{}, err
	}
	return plainID, nil
}
