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

package scrypto

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
	NaClBoxNonceSize = 24
	NaClBoxKeySize   = 32

	Ed25519                    = "ed25519"
	Curve25519xSalsa20Poly1305 = "curve25519xsalsa20poly1305"
)

const (
	InvalidKeySize          = "Invalid key size"
	InvalidNonceSize        = "Invalid nonce size"
	InvalidSignature        = "Invalid signature"
	UnableToGenerateKeyPair = "Unable to generate key pair"
	UnableToGenerateNonce   = "Unable to generate nonce"
	UnableToDecrypt         = "Unable to decrypt message"
	UnsupportedSignAlgo     = "Unsupported signing algorithm"
	UnsupportedEncAlgo      = "Unsupported encryption algorithm"
)

// GenKeyPairs generates a public/private key pair.
func GenKeyPairs(algo string) (common.RawBytes, common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		pubkey, privkey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, common.NewBasicError(UnableToGenerateKeyPair, err,
				"algo", algo)
		}
		return pubkey[:], privkey[:], nil
	case Ed25519:
		pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, common.NewBasicError(UnableToGenerateKeyPair, err,
				"algo", algo)
		}
		return common.RawBytes(pubkey), common.RawBytes(privkey), nil
	default:
		return nil, nil, common.NewBasicError(UnsupportedSignAlgo, nil, "algo", algo)
	}
}

// Sign takes a signature input and a signing key to create a signature. Currently only
// ed25519 is supported.
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

// Nonce takes an input length and returns a random nonce of the given length.
func Nonce(len int) (common.RawBytes, error) {
	if len <= 0 {
		return nil, common.NewBasicError(InvalidNonceSize, nil)
	}
	nonce := make([]byte, len)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, common.NewBasicError(UnableToGenerateNonce, err)
	}
	return nonce, nil
}

// Encrypt takes a message, a nonce and a public/private keypair and
// returns the encrypted and authenticated message.
// Note: Nonce must be different for each message that is encrypted with the same key.
func Encrypt(msg, nonce, pubkey, privkey common.RawBytes, algo string) (common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		if len(nonce) != NaClBoxNonceSize {
			return nil, common.NewBasicError(InvalidNonceSize, nil, "algo", algo)
		}
		if len(pubkey) != NaClBoxKeySize || len(privkey) != NaClBoxKeySize {
			return nil, common.NewBasicError(InvalidKeySize, nil, "algo", algo)
		}
		var nonceRaw [NaClBoxNonceSize]byte
		var pubKeyRaw, privKeyRaw [NaClBoxKeySize]byte
		copy(nonceRaw[:], nonce)
		copy(pubKeyRaw[:], pubkey)
		copy(privKeyRaw[:], privkey)
		return box.Seal(nil, msg, &nonceRaw, &pubKeyRaw, &privKeyRaw), nil
	default:
		return nil, common.NewBasicError(UnsupportedEncAlgo, nil, "algo", algo)
	}
}

// Decrypt decrypts a message for a given nonce and public/private keypair.
func Decrypt(msg, nonce, pubkey, privkey common.RawBytes, algo string) (common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		if len(nonce) != NaClBoxNonceSize {
			return nil, common.NewBasicError(InvalidNonceSize, nil, "algo", algo)
		}
		if len(pubkey) != NaClBoxKeySize || len(privkey) != NaClBoxKeySize {
			return nil, common.NewBasicError(InvalidKeySize, nil, "algo", algo)
		}
		var nonceRaw [NaClBoxNonceSize]byte
		var pubKeyRaw, privKeyRaw [NaClBoxKeySize]byte
		copy(nonceRaw[:], nonce)
		copy(pubKeyRaw[:], pubkey)
		copy(privKeyRaw[:], privkey)
		dec, ok := box.Open(nil, msg, &nonceRaw, &pubKeyRaw, &privKeyRaw)
		if !ok {
			return nil, common.NewBasicError(UnableToDecrypt, nil, "algo", algo)
		}
		return dec, nil
	default:
		return nil, common.NewBasicError(UnsupportedEncAlgo, nil, "algo", algo)
	}
}
