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
	"github.com/gofrs/uuid"
)

type User struct {
	hashedPassword []byte
	salt           []byte
	groups         map[uuid.UUID]bool
}

type SealedUser struct {
	ID         uuid.UUID
	ciphertext []byte
	wrappedKey []byte
}

func (u *User) addGroup(id uuid.UUID) {
	u.groups[id] = true
}

func (u *User) removeGroup(id uuid.UUID) {
	delete(u.groups, id)
}

func (u *User) containsGroup(id uuid.UUID) bool {
	return u.groups[id]
}

func (u *User) getGroups() []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(u.groups))
	for id := range u.groups {
		ids = append(ids, id)
	}
	return ids
}
