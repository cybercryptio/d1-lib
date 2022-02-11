// Copyright 2020-2022 CYBERCRYPT

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
