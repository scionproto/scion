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

package cert_mgmt

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*ChainIssRep)(nil)

type ChainIssRep struct {
	RawChain common.RawBytes `capnp:"chain"`
}

func (c *ChainIssRep) Chain() (*cert.Chain, error) {
	return cert.ChainFromRaw(c.RawChain, true)
}

func (c *ChainIssRep) ProtoId() proto.ProtoIdType {
	return proto.CertChainIssRep_TypeID
}

func (c *ChainIssRep) String() string {
	chain, err := c.Chain()
	if err != nil {
		return fmt.Sprintf("Invalid certificate chain: %v", err)
	}
	return chain.String()
}
