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
