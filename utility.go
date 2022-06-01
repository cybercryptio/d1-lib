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
	"errors"

	"github.com/gofrs/uuid"

	"github.com/cyber-crypt-com/encryptonize-lib/data"
)

// authorizeAccess checks whether the authorizing user is allowed to access the provided access
// object. If so, the unsealed access object is returned.
func (e *Encryptonize) authorizeAccess(authorizer *data.SealedUser, sealedAccess *data.SealedAccess) (data.Access, error) {
	plainAccess, err := sealedAccess.Unseal(e.accessCryptor)
	if err != nil {
		return data.Access{}, err
	}

	plainAuthorizer, err := authorizer.Unseal(e.userCryptor)
	if err != nil {
		return data.Access{}, err
	}

	for id := range plainAuthorizer.GetGroups() {
		if plainAccess.ContainsGroups(id) {
			return plainAccess, nil
		}
	}
	return data.Access{}, errors.New("User not authorized")
}

// authorizeGroups checks whether the authorizing user is a member of all provided groups. If so, a
// list of all the group IDs is returned.
func (e *Encryptonize) authorizeGroups(authorizer *data.SealedUser, groups ...*data.SealedGroup) ([]uuid.UUID, error) {
	groupIDs, err := e.verifyGroups(groups...)
	if err != nil {
		return nil, err
	}

	plainAuthorizer, err := authorizer.Unseal(e.userCryptor)
	if err != nil {
		return nil, err
	}
	if !plainAuthorizer.ContainsGroups(groupIDs...) {
		return nil, errors.New("User not authorized")
	}

	return groupIDs, nil
}

// verifyGroups integrity checks all the provided groups. If they are all authentic, a list of all
// the group IDs is returned.
func (e *Encryptonize) verifyGroups(groups ...*data.SealedGroup) ([]uuid.UUID, error) {
	groupIDs := make([]uuid.UUID, 0, len(groups))
	for _, group := range groups {
		if !group.Verify(e.groupCryptor) {
			return nil, errors.New("Invalid group")
		}
		groupIDs = append(groupIDs, group.ID)
	}
	return groupIDs, nil
}
