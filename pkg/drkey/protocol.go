// Copyright 2022 ETH Zurich
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

package drkey

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

// keyType represents the different types of keys (host->AS, AS->host, host->host).
type KeyType uint8

// Key types.
const (
	AsAs KeyType = iota
	AsHost
	HostAS
	HostHost
)

var (
	ZeroBlock [aes.BlockSize]byte
)

// SerializeHostHostInput serializes the input for deriving a HostHost key,
// as explained in
// https://docs.scion.org/en/latest/cryptography/drkey.html#level-derivation.
// This derivation is common for Generic and Specific derivations.
func SerializeHostHostInput(input []byte, host addr.Host) (int, error) {
	typ, raw, err := slayers.PackAddr(host)
	if err != nil {
		return 0, serrors.Wrap("packing host address", err)
	}
	l := len(raw)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (2+l-1)/16 + 1

	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(HostHost)
	input[1] = uint8(typ & 0xF)
	copy(input[2:], raw)
	copy(input[2+l:inputLength], ZeroBlock[:])

	return inputLength, nil
}

// DeriveKey derives the following key given an input and a higher-level key,
// as stated in
// https://docs.scion.org/en/latest/cryptography/drkey.html#prf-derivation-specification
// The input buffer is overwritten.
func DeriveKey(input []byte, upperLevelKey Key) (Key, error) {
	var key Key
	b, err := initAESCBC(upperLevelKey[:])
	if err != nil {
		return key, err
	}
	mac := cbcMac(b, input[:])
	copy(key[:], mac)
	return key, nil
}

func initAESCBC(key []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.New("Unable to initialize AES cipher")
	}
	mode := cipher.NewCBCEncrypter(block, ZeroBlock[:])
	return mode, nil
}

func cbcMac(block cipher.BlockMode, b []byte) []byte {
	block.CryptBlocks(b, b)
	return b[len(b)-aes.BlockSize:]
}
