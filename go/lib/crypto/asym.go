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
	"crypto/rand"
	"io"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/scionproto/scion/go/lib/common"
)

// Available asymmetric crypto algorithms. The values must be lower case.
const (
	Ed25519                    = "ed25519"
	Curve25519xSalsa20Poly1305 = "curve25519xsalsa20poly1305"
)

const (
	InvalidKeySize           = "Invalid key size"
	InvalidNonceSize         = "Invalid nonce size"
	InvalidSignature         = "Invalid signature"
	FailedToGenerateKeyPairs = "Failed to generate key pairs"
	FailedToGenerateNonce    = "Failed to generate nonce"
	FailedToDecrypt          = "Failed to decrypt message"
	UnsupportedSignAlgo      = "Unsupported signing algorithm"
	UnsupportedEncAlgo       = "Unsupported encryption algorithm"
	UnsupportedDecAlgo       = "Unsupported decryption algorithm"
)

// Sign takes a signature input and a signing key to create a signature. Currently only
// ed25519 is supported
func Sign(sigInput, signKey common.RawBytes, signAlgo string) (common.RawBytes, error) {
	switch strings.ToLower(signAlgo) {
	case Ed25519:
		if len(signKey) != ed25519.PrivateKeySize {
			return nil, common.NewBasicError(InvalidKeySize, nil, "expected",
				ed25519.PrivateKeySize, "actual", len(signKey))
		}
		return ed25519.Sign(ed25519.PrivateKey(signKey), sigInput), nil
	default:
		return nil, common.NewBasicError(UnsupportedSignAlgo, nil, "algo", signAlgo)
	}
}

// Verify takes a signature input and a verifying key and returns an error, if the
// signature does not match. Currently only ed25519 is supported.
func Verify(sigInput, sig, verifyKey common.RawBytes, signAlgo string) error {
	switch strings.ToLower(signAlgo) {
	case Ed25519:
		if len(verifyKey) != ed25519.PublicKeySize {
			return common.NewBasicError(InvalidKeySize, nil,
				"expected", ed25519.PublicKeySize, "actual", len(verifyKey))
		}
		if !ed25519.Verify(ed25519.PublicKey(verifyKey), sigInput, sig) {
			return common.NewBasicError(InvalidSignature, nil)
		}
		return nil
	default:
		return common.NewBasicError(UnsupportedSignAlgo, nil, "algo", signAlgo)
	}
}

// GenKeyPairs generates a public/private key pair
func GenKeyPairs(keygenAlgo string) (common.RawBytes, common.RawBytes, error) {
	switch strings.ToLower(keygenAlgo) {
	case Curve25519xSalsa20Poly1305:
		pubkey, privkey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, common.NewBasicError(FailedToGenerateKeyPairs, err,
				"keygenAlgo", keygenAlgo)
		}
		return pubkey[:], privkey[:], nil
	case Ed25519:
		pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, common.NewBasicError(FailedToGenerateKeyPairs, err,
				"keygenAlgo", keygenAlgo)
		}
		return common.RawBytes(pubkey), common.RawBytes(privkey), nil
	default:
		return nil, nil, common.NewBasicError(UnsupportedSignAlgo, nil, "algo", keygenAlgo)
	}
}

// GenNonce takes an input length and returns a random nonce of the given length
func GenNonce(len uint16) (common.RawBytes, error) {
	nonce := make([]byte, len)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, common.NewBasicError(FailedToGenerateNonce, err)
	}
	return nonce, nil
}

// Encrypt takes a message, a nonce and a public/private keypair and
// returns the encrypted and authenticated message
// Note: Nonce must be different for each message that is encrypted with the same key.
func Encrypt(msg, nonce, pubkey, privkey common.RawBytes, algo string) (common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		if len(nonce) != 24 {
			return nil, common.NewBasicError(InvalidNonceSize, nil, "algo", algo)
		}
		if len(pubkey) != 32 || len(privkey) != 32 {
			return nil, common.NewBasicError(InvalidKeySize, nil, "algo", algo)
		}
		// 192 bits of randomness should provide a sufficiently small probability of repeats.
		var nc *[24]byte
		copy(nc[:], nonce)
		var pubk, privk *[32]byte
		copy(pubk[:], pubkey[:32])
		copy(privk[:], privkey[:32])
		return box.Seal(nil, msg, nc, pubk, privk), nil
	default:
		return nil, common.NewBasicError(UnsupportedEncAlgo, nil, "algo", algo)
	}
}

// Decrypt decrypts a message for a given nonce and public/private keypair
func Decrypt(msg, nonce, pubkey, privkey common.RawBytes, algo string) (common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		if len(nonce) != 24 {
			return nil, common.NewBasicError(InvalidNonceSize, nil, "algo", algo)
		}
		if len(pubkey) != 32 || len(privkey) != 32 {
			return nil, common.NewBasicError(InvalidKeySize, nil, "algo", algo)
		}
		var nc [24]byte
		copy(nc[:], nonce[:24])
		var pubk, privk *[32]byte
		copy(pubk[:], pubkey[:32])
		copy(privk[:], privkey[:32])
		dec, ok := box.Open(nil, msg[24:], &nc, pubk, privk)
		if !ok {
			return nil, common.NewBasicError(FailedToDecrypt, nil, "algo", algo)
		}
		return dec, nil
	default:
		return nil, common.NewBasicError(UnsupportedEncAlgo, nil, "algo", algo)
	}
}
