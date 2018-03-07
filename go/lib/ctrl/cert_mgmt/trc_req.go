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
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*TRCReq)(nil)

type TRCReq struct {
	ISD       uint16 `capnp:"isd"`
	Version   uint64
	CacheOnly bool
}

func (t *TRCReq) IA() addr.IA {
	return addr.IA{I: int(t.ISD), A: 0}
}

func (t *TRCReq) ProtoId() proto.ProtoIdType {
	return proto.TRCReq_TypeID
}

func (t *TRCReq) String() string {
	return fmt.Sprintf("ISD: %d Version: %d CacheOnly: %v", t.ISD, t.Version, t.CacheOnly)
}
