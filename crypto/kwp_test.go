// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

// source: https://github.com/google/tink/blob/22467ef7273d73b2d65e4b50310aab4af006bb7e/go/subtle/kwp/kwp_test.go
// adjusted: package name and remove tink dependencies; added 256 bit wrapping test case

package crypt

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func GetRandomBytes(n uint32) []byte {
	r, err := Random(int(n))
	if err != nil {
		panic(err)
	}
	return r
}

func TestWrapUnwrap(t *testing.T) {
	kek := GetRandomBytes(16)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp, error: %v", err)
	}

	for i := uint32(16); i < 128; i++ {
		t.Run(fmt.Sprintf("MessageSize%d", i), func(t *testing.T) {
			toWrap := GetRandomBytes(i)

			wrapped, err := cipher.Wrap(toWrap)
			if err != nil {
				t.Fatalf("failed to wrap, error: %v", err)
			}

			unwrapped, err := cipher.Unwrap(wrapped)
			if err != nil {
				t.Fatalf("failed to unwrap, error: %v", err)
			}

			if !bytes.Equal(toWrap, unwrapped) {
				t.Error("unwrapped doesn't match original key")
			}
		})
	}
}

func TestKeySizes(t *testing.T) {
	for i := 0; i < 255; i++ {
		expectSuccess := i == 16 || i == 32
		t.Run(fmt.Sprintf("KeySize%d", i), func(t *testing.T) {
			_, err := NewKWP(make([]byte, i))

			if expectSuccess && err != nil {
				t.Errorf("failed to create KWP: %v", err)
			}

			if !expectSuccess && err == nil {
				t.Error("created KWP with invalid key size")
			}
		})
	}
}

func TestInvalidWrappingSizes(t *testing.T) {
	kek := GetRandomBytes(16)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp, error: %v", err)
	}

	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("KeySize%d", i), func(t *testing.T) {
			if _, err := cipher.Wrap(make([]byte, i)); err == nil {
				t.Error("wrapped a short key")
			}
		})
	}
}

func TestKnownVectors(t *testing.T) {
	// vectors from Wycheproof
	vectors := []struct {
		id           int
		key, msg, ct string
	}{
		{
			1,
			"6f67486d1e914419cb43c28509c7c1ea",
			"8dc0632d92ee0be4f740028410b08270",
			"8cd63fa6788aa5edfa753fc87d645a672b14107c3b4519e7",
		},
		{
			76,
			"fce0429c610658ef8e7cfb0154c51de2239a8a317f5af5b6714f985fb5c4d75c",
			"287326b5ed0078e7ca0164d748f667e7",
			"e3eab96d9a2fda12f9e252053aff15e753e5ea6f5172c92b",
		},
		{
			169,
			"aa0ab9d68ed4a04e723f81b44c0c88d0bcde7a80cfd476eb4b8836d9aa01ec4c",
			"57faa8766f6d6a0aa1cf643f857c150df5b31303b50af480e21c4b5e8c8a15d5",
			"0e9e2e9aa34bbf973d67bc534ac86fc5b5a5f9da5f026866177894ec6077a5c84501510e1bf4afb3",
		},
	}

	for _, v := range vectors {
		t.Run(fmt.Sprintf("Vector%d", v.id), func(t *testing.T) {
			kek, err := hex.DecodeString(v.key)
			if err != nil {
				t.Fatal("hex.DecodeString(v.key) => bad kek")
			}

			msg, err := hex.DecodeString(v.msg)
			if err != nil {
				t.Fatal("hex.DecodeString(v.msg) => bad msg")
			}

			ct, err := hex.DecodeString(v.ct)
			if err != nil {
				t.Fatal("hex.DecodeString(v.ct) => bad ciphertext")
			}

			cipher, err := NewKWP(kek)
			if err != nil {
				t.Fatalf("cannot create kwp, error: %v", err)
			}

			wrapped, err := cipher.Wrap(msg)
			if err != nil {
				t.Errorf("cannot wrap, error: %v", err)
			} else if !bytes.Equal(ct, wrapped) {
				t.Error("wrapped key mismatches test vector")
			}

			unwrapped, err := cipher.Unwrap(ct)
			if err != nil {
				t.Errorf("cannot unwrap, error: %v", err)
			} else if !bytes.Equal(msg, unwrapped) {
				t.Error("unwrapped key mismatches test vector")
			}
		})
	}
}
