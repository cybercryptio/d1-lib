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
	ioProvider io.Provider
	idProvider id.Provider

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
		ioProvider: ioProvider,
		idProvider: idProvider,
		indexKey:   keys.IEK,
	}, nil
}

// Add adds a keyword/identifier pair to the secure index.
func (i *SecureIndex) Add(token, keyword, identifier string) error {
	if err := i.verifyAccess(token); err != nil {
		return err
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return err
	}

	// Compute the current last sealed Identifier with the given keyword, i.e. the sealed
	// Identifier with the largest value of the counter.
	last, err := i.lastIdentifier(keyword)
	if err != nil {
		return err
	}

	// Compute new label and plaintext Identifier, seal it, and send it to the IO Provider.
	label, err := last.NextLabel(tagger)
	if err != nil {
		return err
	}

	newID := data.Identifier{Identifier: identifier, NextCounter: last.NextCounter + 1}

	sealedID, err := newID.Seal(label, cryptor)
	if err != nil {
		return err
	}
	if err = i.putSealedIdentifier(label, &sealedID); err != nil {
		return err
	}

	return nil
}

// Given a keyword, Search returns all decrypted Identifiers that the keyword is contained in.
func (i *SecureIndex) Search(token, keyword string) ([]string, error) {
	if err := i.verifyAccess(token); err != nil {
		return nil, err
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return nil, err
	}

	// Starting with label with counter = 0, check if the corresponding sealed Identifier exists in the
	// IO Provider. As long as the sealed Identifier exists, decrypt it, append it to decryptedIDs, and
	// repeat with the next counter value.
	decryptedID := data.Identifier{}
	decryptedIDs := []string{}

	for {
		label, err := decryptedID.NextLabel(tagger)
		if err != nil {
			return nil, err
		}

		// Get the sealed Identifier from the IO Provider. If ErrNotFound, all the Identifiers that contain
		// the given keyword have been found, and the function should return them.
		sealedID, err := i.getSealedIdentifier(label)
		if err == io.ErrNotFound {
			break
		}
		if err != nil {
			return nil, err
		}

		decryptedID, err = sealedID.Unseal(label, cryptor)
		if err != nil {
			return nil, err
		}

		decryptedIDs = append(decryptedIDs, decryptedID.Identifier)
	}

	return decryptedIDs, nil
}

// Delete deletes a keyword/identifier pair from the secure index.
func (i *SecureIndex) Delete(token, keyword, identifier string) error {
	if err := i.verifyAccess(token); err != nil {
		return err
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return err
	}

	// Starting with label with counter = 0, get the corresponding sealed Identifier from
	// the IO Procider, unseal it, and check if its Identifier is equal to the identifier given
	// as input. If not, repeat with the next counter value.
	decryptedID := data.Identifier{}

	for {
		label, err := decryptedID.NextLabel(tagger)
		if err != nil {
			return err
		}

		// Get the sealed Identifier from the IO Provider. If ErrNotFound, there are no more
		// sealed Identifiers to check (and delete), and the function can terminate.
		sealedID, err := i.getSealedIdentifier(label)
		if err == io.ErrNotFound {
			break
		} else if err != nil {
			return err
		}

		// If a sealed Identifier is deleted, it is necessary to check with the same counter
		// once more. Otherwise, two consecutive instances of the same keyword/identifier pair
		// will not both be detected and deleted.
		oldNextCounter := decryptedID.NextCounter

		decryptedID, err = sealedID.Unseal(label, cryptor)
		if err != nil {
			return err
		}

		// Check if the current Identifier matches the identifier given as input.
		if decryptedID.Identifier == identifier {
			err = i.updateCurrentDeleteNext(label, decryptedID, tagger, cryptor)
			// If ErrNotFound, then updateCurrentDeleteNext could not find the next sealed
			// Identifier in the IO Provider. This means that the current decryptedID is the
			// one with the largest value of counter, and hence it can simply be deleted without
			// any other updates.
			if err == io.ErrNotFound {
				if err = i.deleteSealedIdentifier(label); err != nil {
					return err
				}
				break
			} else if err != nil {
				return err
			}

			// Repeat with the same counter once more.
			decryptedID.NextCounter = oldNextCounter
		}
	}
	return nil
}

// updateCurrentDeleteNext is a part of the Delete operation. It updates the current
// Identifier and deletes the next: Instead of changing the label of the next to the
// current label, the Identifier of the current is changed to the Identifier of the
// next, and the next is deleted afterwards. If for example (label: f(1), NextCounter: 2)
// should be deleted, then (label: f(1), NextCounter: 2) and (label: f(2), NextCounter: 3)
// are "converted" to (label: f(1), NextCounter: 3).
func (i *SecureIndex) updateCurrentDeleteNext(currentLabel []byte, currentIdentifier data.Identifier, tagger crypto.TaggerInterface, cryptor crypto.CryptorInterface) error {
	nextLabel, err := currentIdentifier.NextLabel(tagger)
	if err != nil {
		return err
	}
	// Get the sealed ID from the IO Provider. If the next does not exist, then an
	// ErrNotFound is returned and handled in the Delete function.
	nextSealedID, err := i.getSealedIdentifier(nextLabel)
	if err != nil {
		return err
	}

	nextIdentifier, err := nextSealedID.Unseal(nextLabel, cryptor)
	if err != nil {
		return err
	}

	// Update current.
	currentIdentifier.NextCounter = nextIdentifier.NextCounter
	currentIdentifier.Identifier = nextIdentifier.Identifier

	updatedSealedID, err := currentIdentifier.Seal(currentLabel, cryptor)
	if err != nil {
		return err
	}
	if err = i.updateSealedIdentifier(currentLabel, &updatedSealedID); err != nil {
		return err
	}
	// Delete next.
	if err = i.deleteSealedIdentifier(nextLabel); err != nil {
		return err
	}

	return nil
}

// lastIdentifier computes the current last Identifier containing the given keyword, i.e. the
// current Identifier with the largest value of counter.
func (i *SecureIndex) lastIdentifier(keyword string) (data.Identifier, error) {
	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return data.Identifier{}, err
	}

	// Starting with label with counter = 0, check if the corresponding sealed Identifier exists in the
	// IO Provider. As long as the sealed Identifier exists, repeat with the next counter value.
	decryptedID := data.Identifier{}

	for {
		label, err := decryptedID.NextLabel(tagger)
		if err != nil {
			return data.Identifier{}, err
		}

		// Get the sealed Identifier from the IO Provider. If ErrNotFound, then the last Identifier
		//has been found, and the function should return it.
		sealedID, err := i.getSealedIdentifier(label)
		if err == io.ErrNotFound {
			return decryptedID, nil
		} else if err != nil {
			return data.Identifier{}, err
		}

		decryptedID, err = sealedID.Unseal(label, cryptor)
		if err != nil {
			return data.Identifier{}, err
		}
	}
}

// verifyAccess verifies the caller. It verifies both that the caller is authenticated by the
// Identity Provider, and that the caller has the necessary scopes.
func (i *SecureIndex) verifyAccess(token string) error {
	identity, err := i.idProvider.GetIdentity(token)
	if err != nil {
		return ErrNotAuthenticated
	}
	if !identity.Scopes.Contains(id.ScopeIndex) {
		return ErrNotAuthorized
	}

	return nil
}

// getTaggerAndCryptor takes a keyword as input and returns a tagger and a cryptor. The tagger
// is used to create labels based on the value of the counter, and the cryptor is used to seal
// and unseal the Identifiers.
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

// putSealedIdentifier encodes a sealed Identifier and sends it to the IO Provider.
func (i *SecureIndex) putSealedIdentifier(tag []byte, sealedID *data.SealedIdentifier) error {
	var sealedIDBuffer bytes.Buffer
	enc := gob.NewEncoder(&sealedIDBuffer)
	if err := enc.Encode(sealedID); err != nil {
		return err
	}

	label, err := computeLabelUUID(tag)
	if err != nil {
		return err
	}

	return i.ioProvider.Put(label, io.DataTypeSealedID, sealedIDBuffer.Bytes())
}

// updateSealedIdentifier encodes an updated sealed Identifier and updates it in the IO Provider.
func (i *SecureIndex) updateSealedIdentifier(tag []byte, sealedID *data.SealedIdentifier) error {
	var sealedIDBuffer bytes.Buffer
	enc := gob.NewEncoder(&sealedIDBuffer)
	if err := enc.Encode(sealedID); err != nil {
		return err
	}

	label, err := computeLabelUUID(tag)
	if err != nil {
		return err
	}

	return i.ioProvider.Update(label, io.DataTypeSealedID, sealedIDBuffer.Bytes())
}

// getSealedIdentifier fetches bytes from the IO Provider and decodes them into a sealed Identifier.
func (i *SecureIndex) getSealedIdentifier(tag []byte) (*data.SealedIdentifier, error) {
	label, err := computeLabelUUID(tag)
	if err != nil {
		return nil, err
	}

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

// deleteSealedIdentifier deletes a sealed Identifier from the IO Provider.
func (i *SecureIndex) deleteSealedIdentifier(tag []byte) error {
	label, err := computeLabelUUID(tag)
	if err != nil {
		return err
	}

	return i.ioProvider.Delete(label, io.DataTypeSealedID)
}

////////////////////////////////////////////////////////
//                    Conversions                     //
////////////////////////////////////////////////////////

// Given a uint64 counter, compute the tag and return it as a uuid.
func computeLabelUUID(tag []byte) (uuid.UUID, error) {
	// THIS BASEUUID IS PART OF A TEMPORARY SOLUTION AND SHOULD BE DELETED IN AN UPDATED VERSION.
	baseUUID, _ := uuid.FromString("f939afb8-e5fb-47b5-a7b5-784d41252359")

	// Convert label to a uuid.
	return uuidFromString(baseUUID, base64.StdEncoding.EncodeToString(tag)), nil
}

// uuidFromString uses a V5 UUID to get a deterministic ID based on the input.
func uuidFromString(base uuid.UUID, input string) uuid.UUID {
	// We use SHA3 here to avoid any issues with SHA1 which is used in `uuid.NewV5`.
	subjHash := sha3.Sum512([]byte(input))
	return uuid.NewV5(base, string(subjHash[:]))
}
