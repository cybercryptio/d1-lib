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

type Scope uint64

const ScopeNone Scope = 0

const ScopeAll Scope = ScopeEncrypt |
	ScopeDecrypt |
	ScopeUpdate |
	ScopeDelete |
	ScopeCreateToken |
	ScopeGetTokenContents |
	ScopeGetAccessGroups |
	ScopeModifyAccessGroups

const (
	ScopeEncrypt Scope = 1 << iota
	ScopeDecrypt
	ScopeUpdate
	ScopeDelete
	ScopeCreateToken
	ScopeGetTokenContents
	ScopeGetAccessGroups
	ScopeModifyAccessGroups
	ScopeEnd
)

// ScopeUnion returns the union of all the input scopes.
func ScopeUnion(scopes ...Scope) Scope {
	result := ScopeNone
	for _, scope := range scopes {
		result |= scope
	}
	return result
}

// Contains checks wether the scope contains a specific scope.
func (s Scope) Contains(scope Scope) bool {
	return (s & scope) == scope
}
