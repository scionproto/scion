// Copyright 2016 ETH Zurich
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
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/dchest/cmac"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/pkg/private/serrors"
)

var (
	ErrCipherFailure = errors.New("unable to initialize AES cipher")
	ErrMacFailure    = errors.New("unable to initialize Mac")
)

var hfMacSalt = []byte("Derive OF Key")

func InitMac(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.JoinNoStack(ErrCipherFailure, err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.JoinNoStack(ErrMacFailure, err)
	}
	return mac, nil
}

func HFMacFactory(key []byte) (func() hash.Hash, error) {
	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(key, hfMacSalt, 1000, 16, sha256.New)

	// First check for MAC creation errors.
	if _, err := InitMac(hfGenKey); err != nil {
		return nil, err
	}
	f := func() hash.Hash {
		mac, _ := InitMac(hfGenKey)
		return mac
	}
	return f, nil
}
