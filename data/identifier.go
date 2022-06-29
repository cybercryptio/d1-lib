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
	"encoding/binary"

	"github.com/cybercryptio/d1-lib/crypto"
)

// Identifier contains an identifier (e.g. a document ID) and the counter used to compute the next sealed Identifier.
type Identifier struct {
	Identifier  string
	NextCounter uint64
}

// NextLabel computes the next label based on the value of NextCounter.
func (i *Identifier) NextLabel(tagger crypto.TaggerInterface) ([]byte, error) {
	return tagger.Tag(uint64Encode(i.NextCounter))
}

// SealedIdentifier is an encrypted structure which defines an occurrence of a specific keyword in a specific identifier.
type SealedIdentifier struct {
	Ciphertext []byte
	WrappedKey []byte
}

// Seal encrypts the plaintext Identifier.
func (i *Identifier) Seal(label []byte, cryptor crypto.CryptorInterface) (SealedIdentifier, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(i, label)
	if err != nil {
		return SealedIdentifier{}, err
	}

	sealed := SealedIdentifier{
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
	}

	return sealed, nil
}

// Unseal decrypts the sealed Identifier.
func (i *SealedIdentifier) Unseal(label []byte, cryptor crypto.CryptorInterface) (Identifier, error) {
	plainID := Identifier{}
	if err := cryptor.Decrypt(&plainID, label, i.WrappedKey, i.Ciphertext); err != nil {
		return Identifier{}, err
	}
	return plainID, nil
}

// uint64Encode converts an uint64 to a byte array.
func uint64Encode(i uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, i)
	return buf[:n]
}
