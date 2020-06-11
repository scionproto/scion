// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"crypto/x509"
	"fmt"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*ChainRenewalReply)(nil)

// ChainRenewalReply contains the reply for an renewal request.
type ChainRenewalReply struct {
	// RawChain contains the raw chain.
	RawChain  []byte       `capnp:"chain"`
	Signature *proto.SignS `capnp:"sign"`
}

func (c *ChainRenewalReply) ProtoId() proto.ProtoIdType {
	return proto.CertChainRenewalReply_TypeID
}

// Chain parses the raw chain contained in the reply.
func (c *ChainRenewalReply) Chain() ([]*x509.Certificate, error) {
	chain, err := x509.ParseCertificates(c.RawChain)
	if err != nil {
		return nil, serrors.WrapStr("couldn't parse chain", err)
	}
	if err := cppki.ValidateChain(chain); err != nil {
		return nil, serrors.WrapStr("invalid chain", err)
	}
	return chain, nil
}

func (c *ChainRenewalReply) String() string {
	chain, err := c.Chain()
	if err != nil {
		return fmt.Sprintf("Invalid chain: %v", err)
	}
	return chainString(chain)
}
