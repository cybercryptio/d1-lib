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
	"encoding/gob"
	"errors"
	"fmt"

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

	// Compute the current last sealed Identifier containing the given keyword, i.e. the sealed
	// Identifier with the largest value of the counter.
	last, err := i.getLastIdentifier(keyword)
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

// Search returns all decrypted Identifiers that the given keyword is contained in.
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
		// Get the next Identifier. If ErrNotFound, all the Identifiers that contain the given keyword
		// have been found, and the function should return them.
		decryptedID, err = i.getNextIdentifier(decryptedID, tagger, cryptor)
		if err == io.ErrNotFound {
			break
		}
		if err != nil {
			return nil, err
		}

		decryptedIDs = append(decryptedIDs, decryptedID.Identifier)
	}

	return decryptedIDs, nil
}

// Delete deletes all occurrences of a keyword/identifier pair from the secure index.
func (i *SecureIndex) Delete(token, keyword, identifier string) error {
	if err := i.verifyAccess(token); err != nil {
		return err
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return err
	}

	// Starting with label with counter = 0, get the corresponding Identifier and check if
	// its Identifier is equal to the identifier given as input. If not, repeat with the next
	// counter value.
	current := data.Identifier{}

	for {
		// Get the next Identifier. If ErrNotFound, there are no more Identifiers to check (and
		// delete), and the function can terminate.
		next, err := i.getNextIdentifier(current, tagger, cryptor)
		if err == io.ErrNotFound {
			break
		}
		if err != nil {
			return err
		}

		// Check if the next Identifier matches the identifier given as input. In that case, we delete
		// it and check the new value of next in the following iteration.
		if next.Identifier == identifier {
			label, err := current.NextLabel(tagger)
			if err != nil {
				return err
			}
			err = i.deleteIdentifier(label, next, tagger, cryptor)
			if err != nil {
				return err
			}
		} else {
			// If nothing was deleted, we can move on.
			current = next
		}
	}
	return nil
}

// deleteIdentifier is a part of the Delete operation. It deletes an identifier "A" by doing one of
// two things:
// * If "A" is the last identifier, "A" itself is simply deleted.
// * If there is a next identifier "B", "A" is overwritten with "B"s data and "B" is deleted.
func (i *SecureIndex) deleteIdentifier(label []byte, identifier data.Identifier, tagger crypto.TaggerInterface, cryptor crypto.CryptorInterface) error {
	// Get the next Identifier. If ErrNotFound, then the current Identifier is the one
	// with the largest value of counter, and therefore it can simply be deleted without
	// any other updates.
	next, err := i.getNextIdentifier(identifier, tagger, cryptor)
	if err == io.ErrNotFound {
		if err = i.deleteSealedIdentifier(label); err != nil {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	// Overwrite original identifier with the next identifier
	updatedSealedID, err := next.Seal(label, cryptor)
	if err != nil {
		return err
	}
	if err = i.updateSealedIdentifier(label, &updatedSealedID); err != nil {
		return err
	}

	// Delete next.
	nextLabel, err := identifier.NextLabel(tagger)
	if err != nil {
		return err
	}
	if err = i.deleteSealedIdentifier(nextLabel); err != nil {
		return err
	}

	return nil
}

// getLastIdentifier computes the current last Identifier containing the given keyword, i.e. the
// current Identifier with the largest value of counter.
func (i *SecureIndex) getLastIdentifier(keyword string) (data.Identifier, error) {
	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return data.Identifier{}, err
	}

	// Starting with label with counter = 0, check if the corresponding Identifier exists. As long
	// as the Identifier exists, repeat with the next counter value.
	decryptedID := data.Identifier{}

	for {
		// Get the next Identifier. If ErrNotFound, then the last Identifier has been found, and the
		// function should return it.
		nextDecrypted, err := i.getNextIdentifier(decryptedID, tagger, cryptor)
		if err == io.ErrNotFound {
			return decryptedID, nil
		}
		if err != nil {
			return data.Identifier{}, err
		}

		decryptedID = nextDecrypted
	}
}

// getNextIdentifier returns the next Identifier, given a current Identifier.
func (i *SecureIndex) getNextIdentifier(currentIdentifier data.Identifier, tagger crypto.TaggerInterface, cryptor crypto.CryptorInterface) (data.Identifier, error) {
	nextLabel, err := currentIdentifier.NextLabel(tagger)
	if err != nil {
		return data.Identifier{}, err
	}

	// If the next sealed Identifier does not exist in the IO Provider, then an ErrNotFound
	// is returned.
	nextSealedID, err := i.getSealedIdentifier(nextLabel)
	if err != nil {
		return data.Identifier{}, err
	}

	nextIdentifier, err := nextSealedID.Unseal(nextLabel, cryptor)
	if err != nil {
		return data.Identifier{}, err
	}

	return nextIdentifier, nil
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

	return i.ioProvider.Put(tag, io.DataTypeSealedIdentifier, sealedIDBuffer.Bytes())
}

// updateSealedIdentifier encodes an updated sealed Identifier and updates it in the IO Provider.
func (i *SecureIndex) updateSealedIdentifier(tag []byte, sealedID *data.SealedIdentifier) error {
	var sealedIDBuffer bytes.Buffer
	enc := gob.NewEncoder(&sealedIDBuffer)
	if err := enc.Encode(sealedID); err != nil {
		return err
	}

	return i.ioProvider.Update(tag, io.DataTypeSealedIdentifier, sealedIDBuffer.Bytes())
}

// getSealedIdentifier fetches bytes from the IO Provider and decodes them into a sealed Identifier.
func (i *SecureIndex) getSealedIdentifier(tag []byte) (*data.SealedIdentifier, error) {
	sealedIDBytes, err := i.ioProvider.Get(tag, io.DataTypeSealedIdentifier)
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
	return i.ioProvider.Delete(tag, io.DataTypeSealedIdentifier)
}
