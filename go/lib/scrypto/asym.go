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
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Available asymmetric crypto algorithms. The values must be lower case.
const (
	Ed25519                    = "ed25519"
	Curve25519xSalsa20Poly1305 = "curve25519xsalsa20poly1305"
)

// Constants for nacl/box implementation of Curve25519xSalsa20Poly1305
const (
	NaClBoxNonceSize = 24
	NaClBoxKeySize   = 32
)

const (
	ErrInvalidPubKeySize      common.ErrMsg = "Invalid public key size"
	ErrInvalidPrivKeySize     common.ErrMsg = "Invalid private key size"
	ErrInvalidSignatureSize   common.ErrMsg = "Invalid signature size"
	ErrInvalidSignatureFormat common.ErrMsg = "Invalid signature format: " +
		"sig[63]&224 should equal 0"
	ErrVerification            common.ErrMsg = "Signature verification failed"
	ErrUnableToGenerateKeyPair common.ErrMsg = "Unable to generate key pair"
	ErrUnableToDecrypt         common.ErrMsg = "Unable to decrypt message"
	ErrUnsupportedAlgo         common.ErrMsg = "Unsupported algorithm"
	ErrUnsupportedSignAlgo     common.ErrMsg = "Unsupported signing algorithm"
	ErrUnsupportedEncAlgo      common.ErrMsg = "Unsupported encryption algorithm"
)

// GenKeyPair generates a public/private key pair.
func GenKeyPair(algo string) (common.RawBytes, common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		pubkey, privkey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, common.NewBasicError(ErrUnableToGenerateKeyPair, err,
				"algo", algo)
		}
		return pubkey[:], privkey[:], nil
	case Ed25519:
		pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, common.NewBasicError(ErrUnableToGenerateKeyPair, err,
				"algo", algo)
		}
		return common.RawBytes(pubkey), common.RawBytes(privkey), nil
	default:
		return nil, nil, common.NewBasicError(ErrUnsupportedAlgo, nil, "algo", algo)
	}
}

// GetPubKey generates the public key for the provided private key.
func GetPubKey(privKey []byte, algo string) ([]byte, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		var privKeyFixed, pubKey [32]byte
		copy(privKeyFixed[:], privKey)
		curve25519.ScalarBaseMult(&pubKey, &privKeyFixed)
		return pubKey[:], nil
	case Ed25519:
		switch len(privKey) {
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(privKey).Public().(ed25519.PublicKey), nil
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(privKey).Public().(ed25519.PublicKey), nil
		default:
			return nil, serrors.New("unsupported key size", "len", len(privKey), "algo", Ed25519)
		}
	}
	return nil, serrors.New("unsupported key type")
}

// Sign takes a signature input and a signing key to create a signature. Currently only
// ed25519 is supported.
func Sign(sigInput, signKey common.RawBytes, signAlgo string) (common.RawBytes, error) {
	switch strings.ToLower(signAlgo) {
	case Ed25519:
		switch len(signKey) {
		case ed25519.PrivateKeySize:
		case ed25519.SeedSize:
			signKey = common.RawBytes(ed25519.NewKeyFromSeed(signKey))
		default:
			return nil, common.NewBasicError(ErrInvalidPrivKeySize, nil,
				"expected", ed25519.PrivateKeySize, "actual", len(signKey))
		}
		return ed25519.Sign(ed25519.PrivateKey(signKey), sigInput), nil
	default:
		return nil, common.NewBasicError(ErrUnsupportedSignAlgo, nil, "algo", signAlgo)
	}
}

// Verify takes a signature input and a verifying key and returns an error, if the
// signature does not match. Currently only ed25519 is supported.
func Verify(sigInput, sig, verifyKey common.RawBytes, signAlgo string) error {
	switch strings.ToLower(signAlgo) {
	case Ed25519:
		if len(verifyKey) != ed25519.PublicKeySize {
			return common.NewBasicError(ErrInvalidPubKeySize, nil,
				"expected", ed25519.PublicKeySize, "actual", len(verifyKey))
		}
		if len(sig) != ed25519.SignatureSize {
			return common.NewBasicError(ErrInvalidSignatureSize, nil,
				"expected", ed25519.SignatureSize, "actual", len(sig))
		}
		if sig[63]&224 != 0 {
			return common.NewBasicError(ErrInvalidSignatureFormat, nil)
		}
		if !ed25519.Verify(ed25519.PublicKey(verifyKey), sigInput, sig) {
			return common.NewBasicError(ErrVerification, nil, "msg", sigInput)
		}
		return nil
	default:
		return common.NewBasicError(ErrUnsupportedSignAlgo, nil, "algo", signAlgo)
	}
}

// Encrypt takes a message, a nonce and a public/private keypair and
// returns the encrypted and authenticated message.
// Note: Nonce must be different for each message that is encrypted with the same key.
func Encrypt(msg, nonce, pubkey, privkey common.RawBytes, algo string) (common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		nonceRaw, pubKeyRaw, privKeyRaw, err := prepNaClBox(nonce, pubkey, privkey)
		if err != nil {
			return nil, err
		}
		return box.Seal(nil, msg, nonceRaw, pubKeyRaw, privKeyRaw), nil
	default:
		return nil, common.NewBasicError(ErrUnsupportedEncAlgo, nil, "algo", algo)
	}
}

// Decrypt decrypts a message for a given nonce and public/private keypair.
func Decrypt(msg, nonce, pubkey, privkey common.RawBytes, algo string) (common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		nonceRaw, pubKeyRaw, privKeyRaw, err := prepNaClBox(nonce, pubkey, privkey)
		if err != nil {
			return nil, err
		}
		dec, ok := box.Open(nil, msg, nonceRaw, pubKeyRaw, privKeyRaw)
		if !ok {
			return nil, common.NewBasicError(ErrUnableToDecrypt, nil, "algo", algo)
		}
		return dec, nil
	default:
		return nil, common.NewBasicError(ErrUnsupportedEncAlgo, nil, "algo", algo)
	}
}

func prepNaClBox(nonce, pubkey, privkey common.RawBytes) (*[NaClBoxNonceSize]byte,
	*[NaClBoxKeySize]byte, *[NaClBoxKeySize]byte, error) {

	if len(nonce) != NaClBoxNonceSize {
		return nil, nil, nil, common.NewBasicError(ErrInvalidNonceSize, nil, "algo",
			Curve25519xSalsa20Poly1305, "expected size", NaClBoxNonceSize, "actual size",
			len(nonce))
	}
	if len(pubkey) != NaClBoxKeySize {
		return nil, nil, nil, common.NewBasicError(ErrInvalidPubKeySize, nil, "algo",
			Curve25519xSalsa20Poly1305, "expected size", NaClBoxKeySize, "actual size", len(pubkey))
	}
	if len(privkey) != NaClBoxKeySize {
		return nil, nil, nil, common.NewBasicError(ErrInvalidPrivKeySize, nil, "algo",
			Curve25519xSalsa20Poly1305, "expected size", NaClBoxKeySize, "actual size",
			len(privkey))
	}
	var nonceRaw [NaClBoxNonceSize]byte
	var pubKeyRaw, privKeyRaw [NaClBoxKeySize]byte
	copy(nonceRaw[:], nonce)
	copy(pubKeyRaw[:], pubkey)
	copy(privKeyRaw[:], privkey)
	return &nonceRaw, &pubKeyRaw, &privKeyRaw, nil
}
