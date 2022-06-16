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
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/cybercryptio/d1-lib/crypto"
)

// The length of master key, revocation key, and revocation identifier used for searchable encryption.
const MasterKeyLength = 32
const RevocationKeyLength = 32
const RevocationIdentifierLength = 32

// Error returned if a key with invalid length is used for searchable encryption.
var ErrInvalidMasterKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", MasterKeyLength)

// Index contains:
//	- A mapping from string label to SealedID.
//	- A revocation "list" used to keep track of deleted keyword/ID pairs. Each keyword/ID pair is mapped to a boolean.
// If true, then the keyword/ID pair has been deleted. If false, the keyword/ID pair still exists.
type Index struct {
	mapping        map[string]sealedID
	revocationList map[string]bool
}

// SealedID is an encrypted structure which defines an occurrence of a specific keyword in a specific ID.
type sealedID struct {
	ciphertext []byte
	wrappedKey []byte
}

// NewIndex creates an Index which is used to manage keyword/ID pairs.
func NewIndex() Index {
	return Index{mapping: make(map[string]sealedID), revocationList: make(map[string]bool)}
}

// Size returns the total number of entries in the index.
func (i *Index) Size() int {
	return len(i.mapping)
}

// Add adds a keyword/ID pair to the Index.
func (i *Index) Add(key []byte, keyword, id string) error {
	if len(key) != MasterKeyLength {
		return ErrInvalidMasterKeyLength
	}

	// Create three keys, k1, k2, and k3: One for tagger, one for cryptor, and one for creating the revocation identifier, revid.
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("label"), []byte(keyword))
	k2 := crypto.KMACKDF(crypto.EncryptionKeyLength, key, []byte("id"), []byte(keyword))
	k3 := crypto.KMACKDF(RevocationKeyLength, key, []byte("revokeKey"), []byte(keyword))
	revid := crypto.KMACKDF(RevocationIdentifierLength, k3, []byte("revokeId"), []byte(id))

	if i.revocationList[base64.StdEncoding.EncodeToString(revid)] {
		i.revocationList[base64.StdEncoding.EncodeToString(revid)] = false
		return nil
	}

	tagger, err := crypto.NewKMAC256Tagger(k1)
	if err != nil {
		return err
	}
	cryptor, err := crypto.NewAESCryptor(k2)
	if err != nil {
		return err
	}

	// Compute label based on count which is equal to the number of keyword/ID pairs
	// in which the keyword already exists.
	count, err := i.count(key, keyword)
	if err != nil {
		return err
	}
	label, err := tagger.Tag(uint64Encode(count))
	if err != nil {
		return err
	}

	// Encrypt id and wrap it into SealedID.
	wrappedKey, encryptedID, err := cryptor.Encrypt(&id, "")
	if err != nil {
		return err
	}
	sealedID := sealedID{ciphertext: encryptedID, wrappedKey: wrappedKey}

	// Add label/SealedID pair to Index.
	i.mapping[base64.StdEncoding.EncodeToString(label)] = sealedID

	i.revocationList[base64.StdEncoding.EncodeToString(revid)] = false

	return nil
}

// Delete deletes a keyword/ID pair from the Index.
func (i *Index) Delete(key []byte, keyword, id string) error {
	if len(key) != MasterKeyLength {
		return ErrInvalidMasterKeyLength
	}

	// Create key k3 for revocation identifier, revid.
	k3 := crypto.KMACKDF(RevocationKeyLength, key, []byte("revokeKey"), []byte(keyword))
	revid := crypto.KMACKDF(RevocationIdentifierLength, k3, []byte("revokeId"), []byte(id))

	// Set the revocation identifier equal to true in the revocation list.
	i.revocationList[base64.StdEncoding.EncodeToString(revid)] = true

	return nil
}

// Given a keyword, Search returns all decrypted ID's that the keyword is contained in.
func (i *Index) Search(key []byte, keyword string) ([]string, error) {
	if len(key) != MasterKeyLength {
		return nil, ErrInvalidMasterKeyLength
	}

	// Create three keys, k1, k2, and k3: One for tagger, one for cryptor, and one for creating the revocation identifier, revid.
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("label"), []byte(keyword))
	k2 := crypto.KMACKDF(crypto.EncryptionKeyLength, key, []byte("id"), []byte(keyword))
	k3 := crypto.KMACKDF(RevocationKeyLength, key, []byte("revokeKey"), []byte(keyword))

	tagger, err := crypto.NewKMAC256Tagger(k1)
	if err != nil {
		return nil, err
	}
	cryptor, err := crypto.NewAESCryptor(k2)
	if err != nil {
		return nil, err
	}

	decryptedIDs := []string{}

	// For each value of count (starting at 0), check whether the corresponding keyword label
	// exists in Index. As long as the keyword label exists, decrypt the corresponding ID
	// and append it to decryptedIDs. Furthermore, only return IDs for which the revocation identifier
	// is equal to false.
	for count := 0; ; count++ {
		label, err := tagger.Tag(uint64Encode(uint64(count)))
		if err != nil {
			return nil, err
		}

		encryptedID, ok := i.mapping[base64.StdEncoding.EncodeToString(label)]
		if !ok {
			break
		}

		var plaintext string
		if err := cryptor.Decrypt(&plaintext, "", encryptedID.wrappedKey, encryptedID.ciphertext); err != nil {
			return nil, err
		}

		revid := crypto.KMACKDF(RevocationIdentifierLength, k3, []byte("revokeId"), []byte(plaintext))
		if !i.revocationList[base64.StdEncoding.EncodeToString(revid)] {
			decryptedIDs = append(decryptedIDs, plaintext)
		}
	}

	return decryptedIDs, nil
}

func (i *Index) count(key []byte, keyword string) (uint64, error) {
	if len(key) != MasterKeyLength {
		return 0, ErrInvalidMasterKeyLength
	}

	// Create key k1 used for tagger.
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("label"), []byte(keyword))

	tagger, err := crypto.NewKMAC256Tagger(k1)
	if err != nil {
		return 0, err
	}

	// For each value of count (starting at 0), check whether the corresponding keyword label
	// exists in Index. As long as the keyword label exists, increment count.
	for count := 0; ; count++ {
		label, err := tagger.Tag(uint64Encode(uint64(count)))
		if err != nil {
			return 0, err
		}

		if _, ok := i.mapping[base64.StdEncoding.EncodeToString(label)]; !ok {
			return uint64(count), nil
		}
	}
}

func uint64Encode(i uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, i)
	return buf[:n]
}
