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
