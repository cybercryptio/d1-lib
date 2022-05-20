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

package data

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
)

// The length of the master key used for searchable encryption.
const MasterKeyLength = 32

// Error returned if a key with invalid length is used for searchable encryption.
var ErrInvalidMasterKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", MasterKeyLength)

// Index contains a mapping from string label to SealedID.
type Index struct {
	mapping map[string]sealedID
}

// SealedID is an encrypted structure which defines an occurrence of a specific keyword in a specific ID.
type sealedID struct {
	ciphertext []byte
	wrappedKey []byte
}

// NewIndex creates an Index which is used to manage keyword/ID pairs.
func NewIndex() Index {
	return Index{mapping: make(map[string]sealedID)}
}

// Size returns the total number of entries in the index.
func (i *Index) Size() int {
	return len(i.mapping)
}

// Add is used to add a keyword/ID pair to the Index.
func (i *Index) Add(key []byte, keyword, id string) error {
	if len(key) != MasterKeyLength {
		return ErrInvalidMasterKeyLength
	}

	// Create two keys, k1 and k2, one for tagger and one for cryptor.
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("label"), []byte(keyword))
	k2 := crypto.KMACKDF(crypto.EncryptionKeyLength, key, []byte("id"), []byte(keyword))

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

	return nil
}

// Given a keyword, Search returns all decrypted ID's that the keyword is contained in.
func (i *Index) Search(key []byte, keyword string) ([]string, error) {
	if len(key) != MasterKeyLength {
		return nil, ErrInvalidMasterKeyLength
	}

	// Create two keys, k1 and k2, one for tagger and one for cryptor.
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("label"), []byte(keyword))
	k2 := crypto.KMACKDF(crypto.EncryptionKeyLength, key, []byte("id"), []byte(keyword))

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
	// and append it to decryptedIDs.
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
		decryptedIDs = append(decryptedIDs, plaintext)
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
