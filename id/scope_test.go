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

package id

import (
	"testing"

	"math/rand"
	"time"
)

func TestScope(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	scopes := []Scope{
		ScopeEncrypt,
		ScopeDecrypt,
		ScopeUpdate,
		ScopeCreateToken,
		ScopeGetTokenContents,
		ScopeGetAccessGroups,
		ScopeModifyAccessGroups,
	}

	for i := 0; i <= len(scopes); i++ {
		// Randomly order the scopes
		r.Shuffle(len(scopes), func(x, y int) { scopes[x], scopes[y] = scopes[y], scopes[x] })

		// Find the union of the first i scopes
		u := ScopeUnion(scopes[:i]...)

		// Check if the union is correct
		if !u.Contains(ScopeNone) {
			t.Fatalf("Union is missing scopes")
		}

		for j := 0; j < i; j++ {
			if !u.Contains(scopes[j]) {
				t.Fatalf("Union is missing scopes")
			}
		}

		for j := i; j < len(scopes); j++ {
			if u.Contains(scopes[j]) {
				t.Fatalf("Union contains more scopes than expected")
			}
		}
	}
}

func TestScopeRepeatedUnion(t *testing.T) {
	scopes := []Scope{ScopeEncrypt, ScopeUpdate, ScopeGetAccessGroups, ScopeUpdate}
	u := ScopeUnion(scopes...)

	for _, s := range scopes {
		if !u.Contains(s) {
			t.Fatalf("Union is missing scopes")
		}
	}
}
