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

	"github.com/cybercryptio/d1-lib/v2/crypto"
)

// Node contains an identifier (e.g. a document ID) and the counter used to compute the next label.
type Node struct {
	Identifier  string
	NextCounter uint64
}

// NextLabel computes the next label based on the value of NextCounter.
func (n *Node) NextLabel(tagger crypto.TaggerInterface) ([]byte, error) {
	// Converts the NextCounter uint64 to byte array before computing label.
	buf := make([]byte, binary.MaxVarintLen64)
	m := binary.PutUvarint(buf, n.NextCounter)

	return tagger.Tag(buf[:m])
}

// SealedNode is an encrypted structure which defines an occurrence of a specific keyword in a specific identifier.
type SealedNode struct {
	Ciphertext []byte
	WrappedKey []byte
}

// Seal encrypts the plaintext Node.
func (n *Node) Seal(label []byte, cryptor crypto.CryptorInterface) (SealedNode, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(n, label)
	if err != nil {
		return SealedNode{}, err
	}

	return SealedNode{
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
	}, nil
}

// Unseal decrypts the sealed Node.
func (n *SealedNode) Unseal(label []byte, cryptor crypto.CryptorInterface) (Node, error) {
	plainNode := Node{}
	if err := cryptor.Decrypt(&plainNode, label, n.WrappedKey, n.Ciphertext); err != nil {
		return Node{}, err
	}
	return plainNode, nil
}
