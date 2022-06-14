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

package key

// Static implements a Key Provider which returns a fixed set of keys.
type Static struct {
	keys Keys
}

// NewStatic creates a new Static key provider which returns the given Keys.
func NewStatic(keys Keys) Static {
	return Static{keys}
}

// GetKeys returns the static set of keys.
func (s *Static) GetKeys() (Keys, error) {
	return s.keys, nil
}
