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

package crypto

// KMACKDF uses KMAC to derive a `size`-byte cryptographic key from a key initialization key (`kik`),
// a `label`, and a `context`. Implemented according to:
// * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf section 4: KMAC
// * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-draft.pdf section 5.4: KDF Using KMAC
func KMACKDF(size int, kik, label []byte, context ...[]byte) []byte {
	K := NewKMAC256(kik, size, label)
	for _, c := range context {
		K.Write(c)
	}
	return K.Sum(nil)
}
