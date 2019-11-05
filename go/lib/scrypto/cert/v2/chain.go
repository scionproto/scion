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

package cert

import (
	"encoding/json"

	"github.com/scionproto/scion/go/lib/common"
)

// ErrInvalidChainLength indicates an invalid chain length.
const ErrInvalidChainLength common.ErrMsg = "invalid chain length"

// Chain represents the certificate chain.
type Chain struct {
	// Issuer contains the signed issuer certificate.
	Issuer SignedIssuer
	// AS contains the signed AS certificate.
	AS SignedAS
}

// ParseChain parses the raw chain.
func ParseChain(raw []byte) (Chain, error) {
	var chain Chain
	err := json.Unmarshal(raw, &chain)
	return chain, err
}

// UnmarshalJSON unpacks the chain formatted as a json array.
func (c *Chain) UnmarshalJSON(b []byte) error {
	tmp := []interface{}{&c.Issuer, &c.AS}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	if len(tmp) != 2 {
		return common.NewBasicError(ErrInvalidChainLength, nil, "expected", 2, "actual", len(tmp))
	}
	return nil

}

// MarshalJSON packs the chain as a json array.
func (c Chain) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{&c.Issuer, c.AS})
}
