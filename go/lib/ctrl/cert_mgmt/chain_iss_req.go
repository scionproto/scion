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
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*ChainIssReq)(nil)

type ChainIssReq struct {
	RawCert common.RawBytes `capnp:"cert"`
}

func (c *ChainIssReq) Cert() (*cert.Certificate, error) {
	return cert.CertificateFromRaw(c.RawCert)
}

func (c *ChainIssReq) ProtoId() proto.ProtoIdType {
	return proto.CertChainIssReq_TypeID
}

func (c *ChainIssReq) String() string {
	crt, err := c.Cert()
	if err != nil {
		return fmt.Sprintf("Invalid certificate: %v", err)
	}
	return crt.String()
}
