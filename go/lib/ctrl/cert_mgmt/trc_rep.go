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

package cert_mgmt

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/crypto/trc"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*TRCRep)(nil)

type TRCRep struct {
	RawTRC common.RawBytes `capnp:"trc"`
}

func (c *TRCRep) TRC() (*trc.TRC, error) {
	return trc.TRCFromRaw(c.RawTRC, true)
}

func (c *TRCRep) ProtoId() proto.ProtoIdType {
	return proto.TRCRep_TypeID
}

func (c *TRCRep) String() string {
	trc, err := c.TRC()
	if err != nil {
		return fmt.Sprintf("Invalid TRC: %v", err)
	}
	return trc.String()
}
