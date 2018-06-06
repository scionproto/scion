// Copyright 2018 ETH Zurich
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
	mrand "math/rand"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	InvalidNonceSize      = "Invalid nonce size"
	UnableToGenerateNonce = "Unable to generate nonce"
)

func RandUint64() uint64 {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// If this happens, there's some serious problem with the runtime or
		// OS, and there's nothing we can do about it.
		panic("No random numbers available")
	}
	return common.NativeOrder.Uint64(b)
}

// RandInt64 returns a random int64 value. The returned value can be negative.
func RandInt64() int64 {
	return int64(RandUint64())
}

var mathSeedOnce sync.Once

// Seed math/rand's default generator with a random value, once.
func MathRandSeed() {
	mathSeedOnce.Do(func() {
		mrand.Seed(RandInt64())
	})
}

// Nonce takes an input length and returns a random nonce of the given length.
func Nonce(l int) (common.RawBytes, error) {
	if l <= 0 {
		return nil, common.NewBasicError(InvalidNonceSize, nil)
	}
	nonce := make([]byte, l)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, common.NewBasicError(UnableToGenerateNonce, err)
	}
	return nonce, nil
}
