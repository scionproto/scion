// Copyright 2017 ETH Zurich
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

// This file contains the Go representation of TRC requests.

package cert_mgmt

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*TRCReq)(nil)

// TRCReq is the capnp encodable TRC request.
type TRCReq struct {
	ISD    addr.ISD        `capnp:"isd"`
	Base   scrypto.Version `capnp:"base"`
	Serial scrypto.Version `capnp:"serial"`
}

// FromID creates a TRC request from the given ID.
func FromID(id cppki.TRCID) *TRCReq {
	return &TRCReq{
		ISD:    id.ISD,
		Base:   id.Base,
		Serial: id.Serial,
	}
}

// ID returns the TRC ID in this request.
func (t *TRCReq) ID() cppki.TRCID {
	return cppki.TRCID{
		ISD:    t.ISD,
		Base:   t.Base,
		Serial: t.Serial,
	}
}

func (t *TRCReq) ProtoId() proto.ProtoIdType {
	return proto.TRCReq_TypeID
}

func (t *TRCReq) String() string {
	return t.ID().String()
}
