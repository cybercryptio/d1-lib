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

// NewSecureIndex creates a SecureIndex which is used to manage keyword/docID pairs.
func NewSecureIndex(keyProvider key.Provider, ioProvider io.Provider, idProvider id.Provider) (SecureIndex, error) {
	keys, err := keyProvider.GetKeys()
	if err != nil {
		return SecureIndex{}, err
	}

	return SecureIndex{
		keyProvider: keyProvider,
		ioProvider:  ioProvider,
		idProvider:  idProvider,
		indexKey:    keys.IEK,
	}, nil
}

// PlainID contains a document ID and the counter used to compute the next sealed ID.
type PlainID struct {
	DocID       string
	NextCounter uint64
}

// SealedID is an encrypted structure which defines an occurrence of a specific keyword in a specific DocID.
type SealedID struct {
	Ciphertext []byte
	WrappedKey []byte
}

// Seal encrypts the plaintext ID.
func (i *PlainID) Seal(label uuid.UUID, cryptor crypto.CryptorInterface) (SealedID, error) {
	wrappedKey, ciphertext, err := cryptor.Encrypt(i, label)
	if err != nil {
		return SealedID{}, err
	}

	sealed := SealedID{
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
	}

	return sealed, nil
}

// Unseal decrypts the sealed ID.
func (i *SealedID) Unseal(label uuid.UUID, cryptor crypto.CryptorInterface) (PlainID, error) {
	plainID := PlainID{}
	if err := cryptor.Decrypt(&plainID, label.Bytes(), i.WrappedKey, i.Ciphertext); err != nil {
		return PlainID{}, err
	}
	return plainID, nil
}

// Add adds a keyword/docID pair to the secure index.
func (i *SecureIndex) Add(key []byte, token, keyword, docID string) error {
	identity, err := i.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeIndex) {
		return ErrNotAuthorized
	}

	if len(key) != MasterKeyLength {
		return ErrInvalidMasterKeyLength
	}

	// Create two keys, k1 and k2: One for tagger and one for cryptor.
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

	// Compute the current last sealed ID with the given keyword, i.e. the sealed ID with
	// the largest value of the counter.
	lastCounter, lastID, err := i.lastID(key, keyword)
	if err != nil {
		return err
	}

	counter := uint64(0)

	// If the current last sealed ID, lastID, is not an empty sealed ID,
	// i.e. the keyword has already been added to the secure index, do the following.
	if lastID.DocID != "" {
		// Compute the next counter.
		counter = lastCounter + 1

		// Update lastID's NextCounter.
		lastLabelUUID, err := computeLabelUUID(lastCounter, &tagger)
		if err != nil {
			return err
		}

		lastID.NextCounter = counter

		lastSealedID, err := lastID.Seal(lastLabelUUID, &cryptor)
		if err != nil {
			return err
		}
		if err = i.putSealedID(lastLabelUUID, &lastSealedID, true); err != nil {
			return err
		}
	}

	// Compute new labelUUID and plaintext ID, seal it, and send it to the IO Provider.
	labelUUID, err := computeLabelUUID(counter, &tagger)
	if err != nil {
		return err
	}

	plainID := PlainID{DocID: docID, NextCounter: 0}

	sealedID, err := plainID.Seal(labelUUID, &cryptor)
	if err != nil {
		return err
	}
	if err = i.putSealedID(labelUUID, &sealedID, false); err != nil {
		return err
	}

	return nil
}

// Delete deletes a keyword/docID pair from the secure index.
func (i *SecureIndex) Delete(key []byte, token, keyword, docID string) error {
	identity, err := i.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeIndex) {
		return ErrNotAuthorized
	}

	if len(key) != MasterKeyLength {
		return ErrInvalidMasterKeyLength
	}

	// Create two keys, k1 and k2: One for tagger and one for cryptor.
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

	counter := uint64(0)

	previousSealedID := SealedID{}
	previousLabel := uuid.Nil

	// Starting with counter = 0, compute the corresponding sealed ID, unseal it,
	// and check if its DocID is equal to the docID given as input. Otherwise,
	// update counter to the next counter and repeat.
	for {
		labelUUID, err := computeLabelUUID(counter, &tagger)
		if err != nil {
			return err
		}

		// Get the sealed ID from the IO Provider.
		sealedID, err := i.getSealedID(labelUUID)
		if err != nil {
			return err
		}

		decryptedID, err := sealedID.Unseal(labelUUID, &cryptor)
		if err != nil {
			return err
		}

		// Check if the current DocID matches the docID given as input.
		if decryptedID.DocID == docID {
			// Delete the sealed ID.
			if err = i.deleteSealedID(labelUUID); err != nil {
				return err
			}

			if previousSealedID.Ciphertext != nil {
				// In this case, there exists a previous sealed ID which should be updated:
				// The previous sealed ID's next counter should be updated to the deleted sealed ID's next counter.
				return i.updatePreviousAfterDelete(previousLabel, previousSealedID, decryptedID.NextCounter, &cryptor)
			} else if decryptedID.NextCounter != 0 {
				// In this case, there exists a next sealed ID which should be updated:
				// The next sealed ID's counter should be updated to 0 as this sealed ID is now the first.
				return i.updateNextAfterDelete(decryptedID.NextCounter, labelUUID, &cryptor, &tagger)
			}
			// Else, the sealed ID that was deleted was the only sealed ID containing the given keyword,
			// hence nothing else has to be done.
			return nil
		}

		// If there is no next sealed ID, an error should be returned.
		if decryptedID.NextCounter == 0 {
			return err
		}

		counter = decryptedID.NextCounter
		previousSealedID = *sealedID
		previousLabel = labelUUID
	}
}

// Given a keyword, Search returns all decrypted ID's that the keyword is contained in.
func (i *SecureIndex) Search(key []byte, token, keyword string) ([]string, error) {
	identity, err := i.idProvider.GetIdentity(token)
	if err != nil {
		return nil, ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeIndex) {
		return nil, ErrNotAuthorized
	}

	if len(key) != MasterKeyLength {
		return nil, ErrInvalidMasterKeyLength
	}

	// Create two keys, k1 and k2: One for tagger and one for cryptor.
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

	// Starting with counter = 0, check if the corresponding keyword label exists in the secure index.
	// As long as the keyword label exists, decrypt the corresponding ID, append it to decryptedIDs,
	// and update counter to the next counter.
	counter := uint64(0)

	for {
		labelUUID, err := computeLabelUUID(counter, &tagger)
		if err != nil {
			return nil, err
		}

		// Get the sealed ID from the IO Provider.
		sealedID, err := i.getSealedID(labelUUID)
		if err != nil {
			break
		}

		decryptedID, err := sealedID.Unseal(labelUUID, &cryptor)
		if err != nil {
			return nil, err
		}

		decryptedIDs = append(decryptedIDs, decryptedID.DocID)

		if decryptedID.NextCounter == 0 {
			break
		}

		counter = decryptedID.NextCounter
	}

	return decryptedIDs, nil
}

// Compute the current last ID containing the given keyword, i.e. the current ID with the largest value of counter.
func (i *SecureIndex) lastID(key []byte, keyword string) (uint64, PlainID, error) {
	if len(key) != MasterKeyLength {
		return 0, PlainID{}, ErrInvalidMasterKeyLength
	}

	// Create two keys, k1 and k2: One for tagger and one for cryptor.
	k1 := crypto.KMACKDF(crypto.TaggerKeyLength, key, []byte("label"), []byte(keyword))
	k2 := crypto.KMACKDF(crypto.EncryptionKeyLength, key, []byte("id"), []byte(keyword))

	tagger, err := crypto.NewKMAC256Tagger(k1)
	if err != nil {
		return 0, PlainID{}, err
	}
	cryptor, err := crypto.NewAESCryptor(k2)
	if err != nil {
		return 0, PlainID{}, err
	}

	// Starting with counter = 0, check if the corresponding keyword label exists in the secure index.
	// As long as the keyword label exists, update counter to the next counter.
	counter := uint64(0)

	for {
		labelUUID, err := computeLabelUUID(counter, &tagger)
		if err != nil {
			return 0, PlainID{}, err
		}

		sealedID, err := i.getSealedID(labelUUID)
		if err != nil {
			return 0, PlainID{}, nil
		}

		decryptedID, err := sealedID.Unseal(labelUUID, &cryptor)
		if err != nil {
			return 0, PlainID{}, err
		}

		if decryptedID.NextCounter == 0 {
			return counter, decryptedID, nil
		}

		counter = decryptedID.NextCounter
	}
}

// putSealedID encodes a sealed ID and sends it to the IO Provider, either as a "Put" or an "Update".
func (i *SecureIndex) putSealedID(label uuid.UUID, sealedID *SealedID, update bool) error {
	var sealedIDBuffer bytes.Buffer
	enc := gob.NewEncoder(&sealedIDBuffer)
	if err := enc.Encode(sealedID); err != nil {
		return err
	}

	if update {
		return i.ioProvider.Update(label, io.DataTypeSealedID, sealedIDBuffer.Bytes())
	}
	return i.ioProvider.Put(label, io.DataTypeSealedID, sealedIDBuffer.Bytes())
}

// getSealedID fetches bytes from the IO Provider and decodes them into a sealed ID.
func (i *SecureIndex) getSealedID(label uuid.UUID) (*SealedID, error) {
	sealedIDBytes, err := i.ioProvider.Get(label, io.DataTypeSealedID)
	if err != nil {
		return nil, err
	}

	sealedID := &SealedID{}
	dec := gob.NewDecoder(bytes.NewReader(sealedIDBytes))
	err = dec.Decode(sealedID)
	if err != nil {
		return nil, err
	}

	return sealedID, nil
}

// deleteSealedID deletes a sealed ID from the IO Provider.
func (i *SecureIndex) deleteSealedID(label uuid.UUID) error {
	return i.ioProvider.Delete(label, io.DataTypeSealedID)
}

// This is a subfunction of the Delete function. In case the deleted sealed ID is not the
// first sealed ID, this function updates the previous sealed ID:It updates the NextCounter
// of the previous sealed ID to the NextCounter of the sealed ID that was deleted.
func (i *SecureIndex) updatePreviousAfterDelete(previousLabel uuid.UUID, previousSealedID SealedID, nextCounter uint64, cryptor crypto.CryptorInterface) error {
	previousDecryptedID, err := previousSealedID.Unseal(previousLabel, cryptor)
	if err != nil {
		return err
	}
	previousDecryptedID.NextCounter = nextCounter

	previousSealedID, err = previousDecryptedID.Seal(previousLabel, cryptor)
	if err != nil {
		return err
	}
	if err = i.putSealedID(previousLabel, &previousSealedID, true); err != nil {
		return err
	}

	return nil
}

// This is a subfunction of the Delete function. In case the deleted sealed ID is not the
// last sealed ID, this function updates the next sealed ID: It updates the counter of the
// next sealed ID to 0. (It has already been verified that the deleted sealed ID had counter = 0).
func (i *SecureIndex) updateNextAfterDelete(nextCounter uint64, currentLabel uuid.UUID, cryptor crypto.CryptorInterface, tagger crypto.TaggerInterface) error {
	nextLabelUUID, err := computeLabelUUID(nextCounter, tagger)
	if err != nil {
		return err
	}

	// Get the sealed ID from the IO Provider.
	nextSealedID, err := i.getSealedID(nextLabelUUID)
	if err != nil {
		return err
	}

	// As the label of the next sealed ID should be updated (and not the sealed ID itself),
	// it is necessary to delete it and add it with the new label.
	if err = i.deleteSealedID(nextLabelUUID); err != nil {
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

	if err = i.putSealedID(currentLabel, nextSealedID, false); err != nil {
		return err
	}

	return nil
}

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
