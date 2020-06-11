// Copyright 2017 ETH Zurich
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
	"strings"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Chain)(nil)

// Chain is a message that contains certificate chains.
type Chain struct {
	RawChains [][]byte `capnp:"chains"`
}

// NewChain creates a new chain message containing the given chains.
func NewChain(chains [][]*x509.Certificate) *Chain {
	rawChains := make([][]byte, 0, len(chains))
	for _, chain := range chains {
		rawChain := make([]byte, 0, len(chain[0].Raw)+len(chain[1].Raw))
		rawChain = append(rawChain, chain[0].Raw...)
		rawChain = append(rawChain, chain[1].Raw...)
		rawChains = append(rawChains, rawChain)
	}
	return &Chain{RawChains: rawChains}
}

// Chains parses and validates the raw chains encoded in this message.
func (c *Chain) Chains() ([][]*x509.Certificate, error) {
	chains := make([][]*x509.Certificate, 0, len(c.RawChains))
	for i, rawChain := range c.RawChains {
		chain, err := x509.ParseCertificates(rawChain)
		if err != nil {
			return nil, serrors.WrapStr("couldn't parse chain", err, "index", i)
		}
		if err := cppki.ValidateChain(chain); err != nil {
			return nil, serrors.WrapStr("invalid chain", err, "index", i)
		}
		chains = append(chains, chain)
	}
	return chains, nil
}

// ProtoId returns the capnp type ID.
func (c *Chain) ProtoId() proto.ProtoIdType {
	return proto.CertChain_TypeID
}

func (c *Chain) String() string {
	chains, err := c.Chains()
	if err != nil {
		return fmt.Sprintf("Invalid Chains: %v", err)
	}
	printableChains := make([]string, 0, len(chains))
	for _, chain := range chains {
		printableChains = append(printableChains, chainString(chain))
	}
	return fmt.Sprintf("chains:\n%s", strings.Join(printableChains, "\n"))
}

func chainString(chain []*x509.Certificate) string {
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		// should have been validated in c.Chains().
		panic(err)
	}
	return fmt.Sprintf("IA: %s, SubjectKeyID: %x, Validity: [%s, %s]", *ia,
		chain[0].SubjectKeyId, chain[0].NotBefore, chain[0].NotAfter)
}
