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

package encryptonize

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
)

// Index contains a mapping from string label to SealedID.
type Index struct {
	mapping map[string]SealedID
}

// SealedID is an encrypted structure which defines an occurrence of a specific keyword in a specific ID.
type SealedID struct {
	ciphertext []byte
	wrappedKey []byte
}

const MasterKeyLength = 32

var ErrInvalidMasterKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", MasterKeyLength)

// NewSearchable creates an Index which is used to manage keyword/ID pairs.
func NewSearchable() Index {
	return Index{mapping: make(map[string]SealedID)
}
}

// Add is used to add a keyword/ID pair to the Index.
func (i *Index) Add(key []byte, keyword, id string) error {
	if len(key) != MasterKeyLength {
		return ErrInvalidMasterKeyLength
	}

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

	count, err := i.count(key, keyword)
	if err != nil {
		return err
	}
	label, err := tagger.Tag(uint64Encode(count))
	if err != nil {
		return err
	}

	wrappedKey, encryptedID, err := cryptor.Encrypt([]byte(id), "")
	if err != nil {
		return err
	}
	sealedID := SealedID{ciphertext: encryptedID, wrappedKey: wrappedKey}

	i.mapping[base64.StdEncoding.EncodeToString(label)] = sealedID

	return nil
}

// Given a keyword, Search returns all decrypted ID's that the keyword is contained in.
func (i *Index) Search(key []byte, keyword string) ([]string, error) {
	if len(key) != MasterKeyLength {
		return nil, ErrInvalidMasterKeyLength
	}

	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("mac"), []byte(keyword))
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

	for count := 0; ; count++ {
		label, err := tagger.Tag(uint64Encode(uint64(count)))
		if err != nil {
			return nil, err
		}

		encryptedID, ok := i.mapping[base64.StdEncoding.EncodeToString(label)]
		if !ok {
			break
		}

		var plaintext []byte
		err := cryptor.Decrypt(&plaintext, "", encryptedID.wrappedKey, encryptedID.ciphertext)
		if err != nil {
			return nil, err
		}
		decryptedIDs = append(decryptedIDs, string(plaintext))
	}

	return decryptedIDs, nil
}

func (i *Index) count(key []byte, keyword string) (uint64, error) {
	if len(key) != MasterKeyLength {
		return 0, ErrInvalidMasterKeyLength
	}

	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("mac"), []byte(keyword))

	tagger, err := crypto.NewKMAC256Tagger(k1)
	if err != nil {
		return 0, err
	}

	var count uint64

	for j := 0; ; j++ {
		label, err := tagger.Tag(uint64Encode(uint64(j)))
		if err != nil {
			return 0, err
		}

		if _, ok := i.mapping[base64.StdEncoding.EncodeToString(label)]; !ok {
			count = uint64(j)
			break
		}
	}

	return count, nil
}

func uint64Encode(i uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, i)
	return buf[:n]
}
