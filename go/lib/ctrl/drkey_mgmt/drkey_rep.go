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

// This file contains the Go representation of first order DRKey responses.

package drkey_mgmt

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*DRKeyLvl1Rep)(nil)

type DRKeyLvl1Rep struct {
	SrcIA      addr.IAInt `capnp:"isdas"`
	ExpTime    uint32
	Cipher     common.RawBytes
	CertVerSrc uint64
	CertVerDst uint64
}

func (c *DRKeyLvl1Rep) IA() addr.IA {
	return c.SrcIA.IA()
}

func (c *DRKeyLvl1Rep) ProtoId() proto.ProtoIdType {
	return proto.DRKeyLvl1Rep_TypeID
}

// Time returns the expiration time
func (c *DRKeyLvl1Rep) Time() time.Time {
	return util.USecsToTime(uint64(c.ExpTime))
}

func (c *DRKeyLvl1Rep) String() string {
	return fmt.Sprintf("SrcIA: %v ExpTime: %v CertVerSig: %d CertVerEnc: %d",
		c.IA(), util.TimeToString(c.Time()), c.CertVerSrc, c.CertVerDst)
}
