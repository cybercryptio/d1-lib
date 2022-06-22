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
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/sha3"

	"github.com/cybercryptio/d1-lib/crypto"
	"github.com/cybercryptio/d1-lib/io"
)

// The length of master key, revocation key, and revocation identifier used for searchable encryption.
const MasterKeyLength = 32
const RevocationKeyLength = 32
const RevocationIdentifierLength = 32

// Error returned if a key with invalid length is used for searchable encryption.
var ErrInvalidMasterKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", MasterKeyLength)

// Index contains:
//	- A revocation "list" used to keep track of deleted keyword/ID pairs. Each keyword/ID pair is mapped to a boolean.
// If true, then the keyword/ID pair has been deleted. If false, the keyword/ID pair still exists.
type Index struct {
	revocationList map[string]bool
}

// SealedID is an encrypted structure which defines an occurrence of a specific keyword in a specific ID.
type SealedID struct {
	// The label that maps to this sealed ID.
	Label uuid.UUID

	Ciphertext []byte
	WrappedKey []byte
}

// NewIndex creates an Index which is used to manage keyword/ID pairs.
func NewIndex() Index {
	return Index{revocationList: make(map[string]bool)}
}

// Size returns the total number of entries in the index. Note that Size does not take deletions into account. Deleted
// entries are still counted.
func (i *Index) Size() int {
	return len(i.revocationList)
}

// Add adds a keyword/ID pair to the Index.
func (i *Index) Add(key []byte, keyword, id string, ioProvider io.Provider) error {
	if len(key) != MasterKeyLength {
		return ErrInvalidMasterKeyLength
	}

	// THIS BASEUUID IS PART OF A TEMPORARY SOLUTION AND SHOULD BE DELETED IN AN UPDATED VERSION.
	baseUUID, _ := uuid.FromString("f939afb8-e5fb-47b5-a7b5-784d41252359")

	// Create three keys, k1, k2, and k3: One for tagger, one for cryptor, and one for creating the revocation identifier, revid.
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("label"), []byte(keyword))
	k2 := crypto.KMACKDF(crypto.EncryptionKeyLength, key, []byte("id"), []byte(keyword))
	k3 := crypto.KMACKDF(RevocationKeyLength, key, []byte("revokeKey"), []byte(keyword))
	revid := crypto.KMACKDF(RevocationIdentifierLength, k3, []byte("revokeId"), []byte(id))

	// Check if revid is true in revocationList. If yes, true should be changed to false, and the function can terminate.
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
	count, err := i.count(key, keyword, ioProvider)
	if err != nil {
		return err
	}
	label, err := tagger.Tag(uint64Encode(count))
	if err != nil {
		return err
	}
	// Convert label to a uuid.
	labelUUID := uuidFromString(baseUUID, base64.StdEncoding.EncodeToString(label))

	// Encrypt id and wrap it into SealedID.
	wrappedKey, encryptedID, err := cryptor.Encrypt(&id, "")
	if err != nil {
		return err
	}
	sealedID := SealedID{Label: labelUUID, Ciphertext: encryptedID, WrappedKey: wrappedKey}

	// Send sealed ID to the IO Provider.
	if err = i.putSealedID(&sealedID, ioProvider, false); err != nil {
		return err
	}

	// Add the revid to the revocationList. The revid should be false, as the keyword/ID is not revoked.
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

	// Set the revocation identifier to true in the revocation list.
	i.revocationList[base64.StdEncoding.EncodeToString(revid)] = true

	return nil
}

// Given a keyword, Search returns all decrypted ID's that the keyword is contained in.
func (i *Index) Search(key []byte, keyword string, ioProvider io.Provider) ([]string, error) {
	if len(key) != MasterKeyLength {
		return nil, ErrInvalidMasterKeyLength
	}

	// THIS BASEUUID IS PART OF A TEMPORARY SOLUTION AND SHOULD BE DELETED IN AN UPDATED VERSION.
	baseUUID, _ := uuid.FromString("f939afb8-e5fb-47b5-a7b5-784d41252359")

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
	// and append it to decryptedIDs (but only if the corresponding revocation identifier is false).
	for count := 0; ; count++ {
		label, err := tagger.Tag(uint64Encode(uint64(count)))
		if err != nil {
			return nil, err
		}
		// Convert label to a uuid.
		labelUUID := uuidFromString(baseUUID, base64.StdEncoding.EncodeToString(label))

		// Get the sealed ID from the IO Provider.
		sealedID, err := i.getSealedID(labelUUID, ioProvider)
		if err != nil {
			break
		}

		var plaintext string
		if err := cryptor.Decrypt(&plaintext, "", sealedID.WrappedKey, sealedID.Ciphertext); err != nil {
			return nil, err
		}

		revid := crypto.KMACKDF(RevocationIdentifierLength, k3, []byte("revokeId"), []byte(plaintext))
		if !i.revocationList[base64.StdEncoding.EncodeToString(revid)] {
			decryptedIDs = append(decryptedIDs, plaintext)
		}
	}

	return decryptedIDs, nil
}

func (i *Index) count(key []byte, keyword string, ioProvider io.Provider) (uint64, error) {
	if len(key) != MasterKeyLength {
		return 0, ErrInvalidMasterKeyLength
	}

	// THIS BASEUUID IS PART OF A TEMPORARY SOLUTION AND SHOULD BE DELETED IN AN UPDATED VERSION.
	baseUUID, _ := uuid.FromString("f939afb8-e5fb-47b5-a7b5-784d41252359")

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
		// Convert label to a uuid.
		labelUUID := uuidFromString(baseUUID, base64.StdEncoding.EncodeToString(label))

		if _, err = i.getSealedID(labelUUID, ioProvider); err != nil {
			return uint64(count), nil
		}
	}
}

// putSealedID encodes a sealed ID and sends it to the IO Provider, either as a "Put" or an "Update".
func (i *Index) putSealedID(id *SealedID, ioProvider io.Provider, update bool) error {
	var idBuffer bytes.Buffer
	enc := gob.NewEncoder(&idBuffer)
	if err := enc.Encode(id); err != nil {
		return err
	}

	if update {
		return ioProvider.Update(id.Label, io.DataTypeSealedID, idBuffer.Bytes())
	}
	return ioProvider.Put(id.Label, io.DataTypeSealedID, idBuffer.Bytes())
}

// getSealedID fetches bytes from the IO Provider and decodes them into a sealed ID.
func (i *Index) getSealedID(label uuid.UUID, ioProvider io.Provider) (*SealedID, error) {
	idBytes, err := ioProvider.Get(label, io.DataTypeSealedID)
	if err != nil {
		return nil, err
	}

	id := &SealedID{}
	dec := gob.NewDecoder(bytes.NewReader(idBytes))
	err = dec.Decode(id)
	if err != nil {
		return nil, err
	}

	id.Label = label
	return id, nil
}

// deleteSealedID deletes a sealed ID from the IO Provider. (Unused so far, but will soon be used.)
//func (i *Index) deleteSealedID(label uuid.UUID, ioProvider io.Provider) error {
//	return ioProvider.Delete(label, io.DataTypeSealedID)
//}

// uint64Encode converts an uint64 to a byte array.
func uint64Encode(i uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, i)
	return buf[:n]
}

// uuidFromString uses a V5 UUID to get a deterministic ID based on the input.
func uuidFromString(base uuid.UUID, input string) uuid.UUID {
	// We use SHA3 here to avoid any issues with SHA1 which is used in `uuid.NewV5`.
	subjHash := sha3.Sum512([]byte(input))
	return uuid.NewV5(base, string(subjHash[:]))
}
