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
