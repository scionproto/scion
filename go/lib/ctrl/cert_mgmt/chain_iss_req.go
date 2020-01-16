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
	"fmt"

	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*ChainIssReq)(nil)

type ChainIssReq struct {
	Raw []byte `capnp:"cert"`
}

func (c *ChainIssReq) ProtoId() proto.ProtoIdType {
	return proto.CertChainIssReq_TypeID
}

func (c *ChainIssReq) String() string {
	sr, err := renewal.ParseSignedRequest(c.Raw)
	if err != nil {
		return fmt.Sprintf("Invalid renewal req: %v", err)
	}
	r, err := sr.Encoded.Decode()
	if err != nil {
		return fmt.Sprintf("Invalid renewal req(encoded): %v", err)
	}
	ri, err := r.Encoded.Decode()
	if err != nil {
		return fmt.Sprintf("Invalid renewal req(encoded.info): %v", err)
	}
	return fmt.Sprintf("Renewal request: IA: %s, Version: %d, ReqTime: %s",
		ri.Subject, ri.Version, ri.RequestTime)
}
