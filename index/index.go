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
	"context"
	"errors"
	"fmt"

	json "github.com/json-iterator/go"

	"github.com/cybercryptio/d1-lib/v2/crypto"
	"github.com/cybercryptio/d1-lib/v2/data"
	"github.com/cybercryptio/d1-lib/v2/id"
	"github.com/cybercryptio/d1-lib/v2/io"
	"github.com/cybercryptio/d1-lib/v2/key"
	"github.com/cybercryptio/d1-lib/v2/log"
)

// The length of the master key.
const MasterKeyLength = 32

// Error returned if a master key with invalid length is used.
var ErrInvalidMasterKeyLength = fmt.Errorf("invalid key length, accepted key length is %d bytes", MasterKeyLength)

// Error returned if the caller cannot be authenticated by the Identity Provider.
var ErrNotAuthenticated = errors.New("user not authenticated")

// Error returned if a user tries to access data they are not authorized for.
var ErrNotAuthorized = errors.New("user not authorized")

// Error returned if an node was not found in the IO Provider.
var ErrNodeNotFound = errors.New("node not found")

// Error returned if an node already exists in the IO Provider.
var ErrNodeAlreadyExists = errors.New("node already exists")

type SecureIndex struct {
	ioProvider io.Provider
	idProvider id.Provider

	indexKey []byte
}

// NewSecureIndex creates a SecureIndex which is used to manage keyword/identifier pairs.
func NewSecureIndex(ctx context.Context, keyProvider key.Provider, ioProvider io.Provider, idProvider id.Provider) (SecureIndex, error) {
	ctx = log.CopyCtxLogger(ctx)

	log.Ctx(ctx).Debug().Msg("getting keys")
	keys, err := keyProvider.GetKeys(ctx)
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
func (i *SecureIndex) Add(ctx context.Context, token, keyword, identifier string) error {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "add")

	if err := i.verifyAccess(ctx, token); err != nil {
		return err
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return err
	}

	// Compute the current last sealed Node containing the given keyword, i.e. the sealed
	// Node with the largest value of the counter.
	last, err := i.getLastNode(ctx, tagger, cryptor)
	if err != nil {
		return err
	}

	// Compute new label and plaintext Node, seal it, and send it to the IO Provider.
	log.Ctx(ctx).Debug().Msg("adding new node")
	label, err := last.NextLabel(tagger)
	if err != nil {
		return err
	}

	newNode := data.Node{Identifier: identifier, NextCounter: last.NextCounter + 1}

	sealedNode, err := newNode.Seal(label, cryptor)
	if err != nil {
		return err
	}
	if err = i.putSealedNode(ctx, label, &sealedNode, false); err != nil {
		return err
	}

	return nil
}

// Search returns all identifiers that the given keyword is contained in.
func (i *SecureIndex) Search(ctx context.Context, token, keyword string) ([]string, error) {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "search")

	if err := i.verifyAccess(ctx, token); err != nil {
		return nil, err
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return nil, err
	}

	// Starting with label with counter = 0, check if the corresponding sealed Node exists in the
	// IO Provider. As long as the sealed Node exists, decrypt it, append it to decryptedNodes, and
	// repeat with the next counter value.
	decryptedNode := data.Node{}
	identifiers := []string{}

	log.Ctx(ctx).Debug().Msg("searching the index")
	for {
		// Get the next Node. If ErrNodeNotFound, all the identifiers that contain the given keyword
		// have been found, and the function should return them.
		decryptedNode, err = i.getNextNode(ctx, decryptedNode, tagger, cryptor)
		if errors.Is(err, ErrNodeNotFound) {
			break
		}
		if err != nil {
			return nil, err
		}

		identifiers = append(identifiers, decryptedNode.Identifier)
	}

	return identifiers, nil
}

// Delete deletes all occurrences of a keyword/identifier pair from the secure index.
func (i *SecureIndex) Delete(ctx context.Context, token, keyword, identifier string) error {
	ctx = log.CopyCtxLogger(ctx)
	log.WithMethod(ctx, "delete")

	if err := i.verifyAccess(ctx, token); err != nil {
		return err
	}

	tagger, cryptor, err := i.getTaggerAndCryptor(keyword)
	if err != nil {
		return err
	}

	// Starting with label with counter = 0, get the corresponding Node and check if
	// its Identifier is equal to the identifier given as input. If not, repeat with the next
	// counter value.
	current := data.Node{}

	log.Ctx(ctx).Debug().Msg("deleting entries from index")
	for {
		// Get the next Node. If ErrNodeNotFound, there are no more Nodes to check (and
		// delete), and the function can terminate.
		next, err := i.getNextNode(ctx, current, tagger, cryptor)
		if errors.Is(err, ErrNodeNotFound) {
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
			err = i.deleteNode(ctx, label, next, tagger, cryptor)
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

// deleteNode is a part of the Delete operation. It deletes a node "A" by doing one of
// two things:
// * If "A" is the last node, "A" itself is simply deleted.
// * If there is a next node "B", "A" is overwritten with "B"s data and "B" is deleted.
func (i *SecureIndex) deleteNode(ctx context.Context, label []byte, node data.Node, tagger crypto.TaggerInterface, cryptor crypto.CryptorInterface) error {
	log.Ctx(ctx).Debug().Msg("deleting node")

	// Get the next Node. If ErrNodeNotFound, then the current Node is the one
	// with the largest value of counter, and therefore it can simply be deleted without
	// any other updates.
	next, err := i.getNextNode(ctx, node, tagger, cryptor)
	if errors.Is(err, ErrNodeNotFound) {
		log.Ctx(ctx).Debug().Msg("last node, deleting")
		if err = i.deleteSealedNode(ctx, label); err != nil {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	// Overwrite original node with the next node
	log.Ctx(ctx).Debug().Msg("overwriting with next node")
	updatedSealedNode, err := next.Seal(label, cryptor)
	if err != nil {
		return err
	}
	if err := i.putSealedNode(ctx, label, &updatedSealedNode, true); err != nil {
		return err
	}

	// Delete next.
	log.Ctx(ctx).Debug().Msg("deleting next node")
	nextLabel, err := node.NextLabel(tagger)
	if err != nil {
		return err
	}
	if err := i.deleteSealedNode(ctx, nextLabel); err != nil {
		return err
	}

	return nil
}

// getLastNode computes the current last Node containing the given keyword, i.e. the
// current Node with the largest value of counter.
func (i *SecureIndex) getLastNode(ctx context.Context, tagger crypto.TaggerInterface, cryptor crypto.CryptorInterface) (data.Node, error) {
	log.Ctx(ctx).Debug().Msg("getting last node")

	// Starting with label with counter = 0, check if the corresponding Node exists. As long
	// as the Node exists, repeat with the next counter value.
	decryptedNode := data.Node{}

	for {
		// Get the next Node. If ErrNodeNotFound, then the last Node has been found, and the
		// function should return it.
		nextDecrypted, err := i.getNextNode(ctx, decryptedNode, tagger, cryptor)
		if errors.Is(err, ErrNodeNotFound) {
			return decryptedNode, nil
		}
		if err != nil {
			return data.Node{}, err
		}

		decryptedNode = nextDecrypted
	}
}

// getNextNode returns the next Node, given a current Node.
func (i *SecureIndex) getNextNode(ctx context.Context, currentNode data.Node, tagger crypto.TaggerInterface, cryptor crypto.CryptorInterface) (data.Node, error) {
	log.Ctx(ctx).Debug().Msg("getting next node")

	nextLabel, err := currentNode.NextLabel(tagger)
	if err != nil {
		return data.Node{}, err
	}

	// If the next sealed Node does not exist in the IO Provider, then an ErrNodeNotFound
	// is returned.
	nextSealedNode, err := i.getSealedNode(ctx, nextLabel)
	if err != nil {
		return data.Node{}, err
	}

	nextNode, err := nextSealedNode.Unseal(nextLabel, cryptor)
	if err != nil {
		return data.Node{}, err
	}

	return nextNode, nil
}

// verifyAccess verifies the caller. It verifies both that the caller is authenticated by the
// Identity Provider, and that the caller has the necessary scopes.
func (i *SecureIndex) verifyAccess(ctx context.Context, token string) error {
	log.Ctx(ctx).Debug().Msg("authenticating caller")
	identity, err := i.idProvider.GetIdentity(ctx, token)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Msg("authentication failed")
		return ErrNotAuthenticated
	}
	log.WithUserID(ctx, identity.ID)

	log.Ctx(ctx).Debug().Msg("authorizing caller")
	if !identity.Scopes.Contains(id.ScopeIndex) {
		log.Ctx(ctx).Debug().Stringer("scope", id.ScopeIndex).Msg("scope missing")
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

// putSealedNode encodes a sealed Node and sends it to the IO Provider, either as a "Put" or an
// "Update".
func (i *SecureIndex) putSealedNode(ctx context.Context, tag []byte, sealedNode *data.SealedNode, update bool) error {
	log.Ctx(ctx).Debug().Msg("storing node")

	sealedNodeBytes, err := json.Marshal(sealedNode)
	if err != nil {
		return err
	}

	if update {
		log.Ctx(ctx).Debug().Msg("updating stored node")
		err := i.ioProvider.Update(ctx, tag, io.DataTypeSealedNode, sealedNodeBytes)
		if errors.Is(err, io.ErrNotFound) {
			return ErrNodeNotFound
		}
		return err
	}

	log.Ctx(ctx).Debug().Msg("creating new node")
	err = i.ioProvider.Put(ctx, tag, io.DataTypeSealedNode, sealedNodeBytes)
	if errors.Is(err, io.ErrAlreadyExists) {
		return ErrNodeAlreadyExists
	}
	return err
}

// getSealedNode fetches bytes from the IO Provider and decodes them into a sealed Node.
func (i *SecureIndex) getSealedNode(ctx context.Context, tag []byte) (*data.SealedNode, error) {
	log.Ctx(ctx).Debug().Msg("getting stored node")

	sealedNodeBytes, err := i.ioProvider.Get(ctx, tag, io.DataTypeSealedNode)
	if errors.Is(err, io.ErrNotFound) {
		return nil, ErrNodeNotFound
	}
	if err != nil {
		return nil, err
	}

	sealedNode := &data.SealedNode{}
	if err := json.Unmarshal(sealedNodeBytes, sealedNode); err != nil {
		return nil, err
	}

	return sealedNode, nil
}

// deleteSealedNode deletes a sealed Node from the IO Provider.
func (i *SecureIndex) deleteSealedNode(ctx context.Context, tag []byte) error {
	log.Ctx(ctx).Debug().Msg("deleting stored node")
	return i.ioProvider.Delete(ctx, tag, io.DataTypeSealedNode)
}
