// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"strings"

	"golang.org/x/crypto/ed25519"

	"github.com/netsec-ethz/scion/go/lib/common"
)

const (
	Ed25519                    = "ed25519"
	Curve25519xSalsa20Poly1305 = "curve25519xsalsa20poly1305"
	InvalidKeySize             = "Invalid key size"
	UnsupportedSignAlgo        = "Unsupported signing algorithm"
	InvalidSignature           = "Invalid signature"
)

// Sign takes a signature input and a signing key to create a signature. Currently only
// ed25519 is supported
func Sign(sigInput, signKey common.RawBytes, signAlgo string) (common.RawBytes, error) {
	switch strings.ToLower(signAlgo) {
	case Ed25519:
		if len(signKey) != ed25519.PrivateKeySize {
			return nil, common.NewCError(InvalidKeySize, "expected",
				ed25519.PrivateKeySize, "actual", len(signKey))
		}
		return ed25519.Sign(ed25519.PrivateKey(signKey), sigInput), nil
	default:
		return nil, common.NewCError(UnsupportedSignAlgo, "algo", signAlgo)
	}
}

// Verify takes a signature input and a verifying key and returns an error, if the
// signature does not match. Currently only ed25519 is supported.
func Verify(sigInput, sig, verifyKey common.RawBytes, signAlgo string) error {
	switch strings.ToLower(signAlgo) {
	case Ed25519:
		if len(verifyKey) != ed25519.PublicKeySize {
			return common.NewCError(InvalidKeySize, "expected",
				ed25519.PublicKeySize, "actual", len(verifyKey))
		}
		if !ed25519.Verify(ed25519.PublicKey(verifyKey), sigInput, sig) {
			return common.NewCError(InvalidSignature)
		}
		return nil
	default:
		return common.NewCError(UnsupportedSignAlgo, "algo", signAlgo)
	}
}
