package id

type Scope uint64

const ScopeNone Scope = 0

const ScopeAll Scope = ScopeEncrypt |
	ScopeDecrypt |
	ScopeUpdate |
	ScopeCreateToken |
	ScopeGetTokenContents |
	ScopeGetAccessGroups |
	ScopeModifyAccessGroups

const (
	ScopeEncrypt Scope = 1 << iota
	ScopeDecrypt
	ScopeUpdate
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
