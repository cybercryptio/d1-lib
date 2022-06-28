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

package index

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/sha3"

	"github.com/cybercryptio/d1-lib/crypto"
	"github.com/cybercryptio/d1-lib/data"
	"github.com/cybercryptio/d1-lib/id"
	"github.com/cybercryptio/d1-lib/io"
	"github.com/cybercryptio/d1-lib/key"
)

// The length of the master key.
const MasterKeyLength = 32

// Error returned if a master key with invalid length is used.
var ErrInvalidMasterKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", MasterKeyLength)

// Error returned if the caller cannot be authenticated by the Identity Provider.
var ErrNotAuthenticated = errors.New("user not authenticated")

// Error returned if a user tries to access data they are not authorized for.
var ErrNotAuthorized = errors.New("user not authorized")

type SecureIndex struct {
	keyProvider key.Provider
	ioProvider  io.Provider
	idProvider  id.Provider

	indexKey []byte
}

// NewSecureIndex creates a SecureIndex which is used to manage keyword/identifier pairs.
func NewSecureIndex(keyProvider key.Provider, ioProvider io.Provider, idProvider id.Provider) (SecureIndex, error) {
	keys, err := keyProvider.GetKeys()
	if err != nil {
		return SecureIndex{}, err
	}

	if len(keys.IEK) != MasterKeyLength {
		return SecureIndex{}, ErrInvalidMasterKeyLength
	}

	return SecureIndex{
		keyProvider: keyProvider,
		ioProvider:  ioProvider,
		idProvider:  idProvider,
		indexKey:    keys.IEK,
	}, nil
}

// Add adds a keyword/identifier pair to the secure index.
func (i *SecureIndex) Add(token, keyword, identifier string) error {
	identity, err := i.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeIndex) {
		return ErrNotAuthorized
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return err
	}

	// Compute the current last sealed Identifier with the given keyword, i.e. the sealed
	// Identifier with the largest value of the counter.
	lastIdentifier, err := i.lastIdentifier(keyword)
	if err != nil {
		return err
	}

	// Compute new labelUUID and plaintext Identifier, seal it, and send it to the IO Provider.
	labelUUID, err := computeLabelUUID(lastIdentifier.NextCounter, tagger)
	if err != nil {
		return err
	}

	plainID := data.Identifier{Identifier: identifier, NextCounter: lastIdentifier.NextCounter + 1}

	sealedID, err := plainID.Seal(labelUUID, cryptor)
	if err != nil {
		return err
	}
	if err = i.putSealedIdentifier(labelUUID, &sealedID); err != nil {
		return err
	}

	return nil
}

// Given a keyword, Search returns all decrypted Identifiers that the keyword is contained in.
func (i *SecureIndex) Search(token, keyword string) ([]string, error) {
	identity, err := i.idProvider.GetIdentity(token)
	if err != nil {
		return nil, ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeIndex) {
		return nil, ErrNotAuthorized
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return nil, err
	}

	decryptedIDs := []string{}

	// Starting with counter = 0, check if the corresponding keyword label exists in the secure index.
	// As long as the keyword label exists, decrypt the corresponding Identifier, append it to decryptedIDs,
	// and update counter to the next counter.
	counter := uint64(0)

	for {
		labelUUID, err := computeLabelUUID(counter, tagger)
		if err != nil {
			return nil, err
		}

		// Get the sealed ID from the IO Provider. If error, all the Identifiers have been found, and the
		// function can return them.
		sealedID, err := i.getSealedIdentifier(labelUUID)
		if err != nil {
			break
		}

		decryptedID, err := sealedID.Unseal(labelUUID, cryptor)
		if err != nil {
			return nil, err
		}

		decryptedIDs = append(decryptedIDs, decryptedID.Identifier)

		counter = decryptedID.NextCounter
	}

	return decryptedIDs, nil
}

// Delete deletes a keyword/identifier pair from the secure index.
func (i *SecureIndex) Delete(token, keyword, identifier string) error {
	identity, err := i.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeIndex) {
		return ErrNotAuthorized
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return err
	}

	// A map that keeps track of which labels should be updated after deletions.
	// It is necessary to first update labels after deletions (as the same keyword/
	// identifier pair can occur more than once in the secure index).
	labelUpdates := make(map[uint64]uuid.UUID)

	counter := uint64(0)

	// Starting with counter = 0, compute the corresponding sealed Identifier, unseal it,
	// and check if its Identifier is equal to the identifier given as input. Otherwise,
	// update counter to the next counter and repeat.
	for {
		labelUUID, err := computeLabelUUID(counter, tagger)
		if err != nil {
			return err
		}

		// Get the sealed ID from the IO Provider.
		sealedID, err := i.getSealedIdentifier(labelUUID)
		if err != nil {
			// No more deletions, and hence the labels can be updated.
			for counter, label := range labelUpdates {
				if err = i.updateLabelOfNext(counter, label, cryptor, tagger); err != nil {
					return err
				}
			}
			return nil
		}

		decryptedID, err := sealedID.Unseal(labelUUID, cryptor)
		if err != nil {
			return err
		}

		// Check if the current Identifier matches the identifier given as input.
		if decryptedID.Identifier == identifier {
			// Delete the sealed ID.
			if err = i.deleteSealedIdentifier(labelUUID); err != nil {
				return err
			}

			// Add the next counter and label such that the next label will be updated to current label later.
			labelUpdates[decryptedID.NextCounter] = labelUUID
		}

		counter = decryptedID.NextCounter
	}
}

// updateLabelOfNext updates the next label (with counter equal to nextCounter) to current label.
// This operation is necessary after deletions.
func (i *SecureIndex) updateLabelOfNext(nextCounter uint64, currentLabel uuid.UUID, cryptor crypto.CryptorInterface, tagger crypto.TaggerInterface) error {
	nextLabelUUID, err := computeLabelUUID(nextCounter, tagger)
	if err != nil {
		return err
	}

	// Get the sealed ID from the IO Provider. If error, the next sealed Identifier does not exist,
	// and the function can terminate.
	nextSealedID, err := i.getSealedIdentifier(nextLabelUUID)
	if err != nil {
		return nil
	}

	// As the label of the next sealed ID should be updated (and not the sealed ID itself),
	// it is necessary to delete it and add it with the new label.
	if err = i.deleteSealedIdentifier(nextLabelUUID); err != nil {
		return err
	}

	nextDecryptedID, err := nextSealedID.Unseal(nextLabelUUID, cryptor)
	if err != nil {
		return err
	}

	*nextSealedID, err = nextDecryptedID.Seal(currentLabel, cryptor)
	if err != nil {
		return err
	}

	if err = i.putSealedIdentifier(currentLabel, nextSealedID); err != nil {
		return err
	}

	return nil
}

// Compute the current last Identifier containing the given keyword, i.e. the current Identifier with
// the largest value of counter.
func (i *SecureIndex) lastIdentifier(keyword string) (data.Identifier, error) {
	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return data.Identifier{}, err
	}

	// Starting with counter = 0, check if the corresponding keyword label exists in the secure index.
	// As long as the keyword label exists, update counter to the next counter.
	counter := uint64(0)

	decryptedID := data.Identifier{}

	for {
		labelUUID, err := computeLabelUUID(counter, tagger)
		if err != nil {
			return data.Identifier{}, err
		}

		// Get the sealed Identifier from the IO Provider. If error, then the last Identifier has already
		// been found, and the function can return it.
		sealedID, err := i.getSealedIdentifier(labelUUID)
		if err != nil {
			return decryptedID, nil
		}

		decrypted, err := sealedID.Unseal(labelUUID, cryptor)
		if err != nil {
			return data.Identifier{}, err
		}

		counter = decryptedID.NextCounter
		decryptedID = decrypted
	}
}

// getTaggerAndCryptor takes a keyword as input and returns a tagger and a cryptor.
func (i *SecureIndex) getTaggerAndCryptor(keyword string) (crypto.TaggerInterface, crypto.CryptorInterface, error) {
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, i.indexKey, []byte("label"), []byte(keyword))
	k2 := crypto.KMACKDF(crypto.EncryptionKeyLength, i.indexKey, []byte("id"), []byte(keyword))

	tagger, err := crypto.NewKMAC256Tagger(k1)
	if err != nil {
		return nil, nil, err
	}
	cryptor, err := crypto.NewAESCryptor(k2)
	if err != nil {
		return nil, nil, err
	}

	return &tagger, &cryptor, nil
}

////////////////////////////////////////////////////////
//                    IO Provider                     //
////////////////////////////////////////////////////////

// putSealedID encodes a sealed ID and sends it to the IO Provider.
func (i *SecureIndex) putSealedIdentifier(label uuid.UUID, sealedID *data.SealedIdentifier) error {
	var sealedIDBuffer bytes.Buffer
	enc := gob.NewEncoder(&sealedIDBuffer)
	if err := enc.Encode(sealedID); err != nil {
		return err
	}

	return i.ioProvider.Put(label, io.DataTypeSealedID, sealedIDBuffer.Bytes())
}

// getSealedID fetches bytes from the IO Provider and decodes them into a sealed ID.
func (i *SecureIndex) getSealedIdentifier(label uuid.UUID) (*data.SealedIdentifier, error) {
	sealedIDBytes, err := i.ioProvider.Get(label, io.DataTypeSealedID)
	if err != nil {
		return nil, err
	}

	sealedID := &data.SealedIdentifier{}
	dec := gob.NewDecoder(bytes.NewReader(sealedIDBytes))
	err = dec.Decode(sealedID)
	if err != nil {
		return nil, err
	}

	return sealedID, nil
}

// deleteSealedID deletes a sealed ID from the IO Provider.
func (i *SecureIndex) deleteSealedIdentifier(label uuid.UUID) error {
	return i.ioProvider.Delete(label, io.DataTypeSealedID)
}

////////////////////////////////////////////////////////
//                    Conversions                     //
////////////////////////////////////////////////////////

// Given a uint64 counter, compute the tag and return it as a uuid.
func computeLabelUUID(counter uint64, tagger crypto.TaggerInterface) (uuid.UUID, error) {
	// THIS BASEUUID IS PART OF A TEMPORARY SOLUTION AND SHOULD BE DELETED IN AN UPDATED VERSION.
	baseUUID, _ := uuid.FromString("f939afb8-e5fb-47b5-a7b5-784d41252359")

	tag, err := tagger.Tag(uint64Encode(counter))
	if err != nil {
		return uuid.Nil, err
	}
	// Convert label to a uuid.
	return uuidFromString(baseUUID, base64.StdEncoding.EncodeToString(tag)), nil
}

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
