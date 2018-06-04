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

// This file contains the Go representation of Certificate Chain requests.

package drkey

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*DRKeyReq)(nil)

type DRKeyReq struct {
	SrcIA     addr.IAInt `capnp:"isdas"`
	Timestamp uint64
	Signature common.RawBytes
	CertVer   uint32
	TrcVer    uint32
	Flags     struct {
		Prefetch bool
	}
}

func (c *DRKeyReq) IA() addr.IA {
	return c.SrcIA.IA()
}

func (c *DRKeyReq) ProtoId() proto.ProtoIdType {
	return proto.DRKeyReq_TypeID
}

func (c *DRKeyReq) String() string {
	return fmt.Sprintf("Src ISD-AS: %s Timestamp: %v CertVersion: %v TRCVersion: %v Prefetch: %v",
		c.IA(), c.Timestamp, c.CertVer, c.TrcVer, c.Flags.Prefetch)
}
