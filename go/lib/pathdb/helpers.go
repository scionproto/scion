// Copyright 2019 Anapaya Systems
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

package pathdb

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/pathpol"
)

// PolicyHashFunc is a function that hashes a policy.
type PolicyHashFunc func(policy *pathpol.Policy) (PolicyHash, error)

// PolicyHash is the hash of a policy.
type PolicyHash []byte

// NoPolicy should be used instead of nil when inserting policy hashes into
// fields which can't be null in the DB.
var NoPolicy = PolicyHash{0x44, 0x13, 0x6f, 0xa3, 0x55, 0xb3, 0x67, 0x8a, 0x11, 0x46, 0xad, 0x16,
	0xf7, 0xe8, 0x64, 0x9e, 0x94, 0xfb, 0x4f, 0xc2, 0x1f, 0xe7, 0x7e, 0x83, 0x10, 0xc0, 0x60, 0xf6,
	0x1c, 0xaa, 0xff, 0x8a}

// HashPolicy is a default implementation of a policy hash function. It creates
// a sha256 hash of the json serialized policy.
func HashPolicy(policy *pathpol.Policy) (PolicyHash, error) {
	pol := policy
	if pol == nil {
		pol = &pathpol.Policy{}
	}
	jsonPol, err := json.Marshal(pol)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(jsonPol)
	return h.Sum(nil), nil
}

func (h PolicyHash) String() string {
	return common.RawBytes(h).String()
}
