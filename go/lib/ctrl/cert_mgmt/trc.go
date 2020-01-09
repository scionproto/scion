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
	"fmt"

	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*TRC)(nil)

type TRC struct {
	RawTRC []byte `capnp:"trc"`
}

func (t *TRC) ProtoId() proto.ProtoIdType {
	return proto.TRC_TypeID
}

func (t *TRC) String() string {
	signed, err := trc.ParseSigned(t.RawTRC)
	if err != nil {
		return fmt.Sprintf("Invalid signed TRC: %v", err)
	}
	pld, err := signed.EncodedTRC.Decode()
	if err != nil {
		return fmt.Sprintf("Invalid TRC payload: %v", err)
	}
	return fmt.Sprintf("ISD%d-V%d", pld.ISD, pld.Version)
}
