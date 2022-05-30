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

func ScopeUnion(scopes ...Scope) Scope {
	result := ScopeNone
	for _, scope := range scopes {
		result |= scope
	}
	return result
}

func (s Scope) Contains(scope Scope) bool {
	return (s & scope) == scope
}
