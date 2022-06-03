// Package key contains the definition of the Key Provider, as well as various implementations of
// the concept.
package key

// Keys contains the master key material used by Encryptonize. All keys must be 32 bytes.
type Keys struct {
	// Object Encryption Key used for sealing Objects.
	KEK []byte `koanf:"kek"`

	// Access Encryption Key used for sealing Access lists.
	AEK []byte `koanf:"aek"`

	// Token Encryption Key used for sealing Tokens.
	TEK []byte `koanf:"tek"`

	// Index Encryption Key used for searchable encryption.
	IEK []byte `koanf:"iek"`
}

// Provider is the interface a Key Provider must implement to serve keys to Encryptonize.
type Provider interface {
	// GetKeys returns a set of keys.
	GetKeys() (Keys, error)
}
