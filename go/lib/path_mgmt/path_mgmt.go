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

package path_mgmt

import (
	"github.com/netsec-ethz/scion/go/lib/pcb"
	"github.com/netsec-ethz/scion/go/proto"
)

type PathMgmt struct {
	Which        proto.PathMgmt
	SegReq       SegReq
	SegReply     SegRecs
	SegSync      SegRecs
	RevInfo      RevInfo
	IFStateReq   IFStateReq   `capnp:"ifStateReq"`
	IFStateInfos IFStateInfos `capnp:"ifStateInfos"`
}

type SegReq struct {
	RawSrcIA uint32 `capnp:"srcIA"`
	RawDstIA uint32 `capnp:"dstIA"`
	Flags    struct {
		Sibra     bool
		CacheOnly bool
	}
}

type SegRecs struct {
	Recs     []pcb.Meta
	RevInfos []RevInfo
}

type RevInfo struct {
	IfID     uint64
	Epoch    uint16
	Nonce    []byte
	Sibling  []SiblingHash
	PrevRoot []byte
	NextRoot []byte
	Isdas    uint32
}

type SiblingHash struct {
	IsLeft bool
	Hash   []byte
}

type IFStateReq struct {
	IfID uint64
}

type IFStateInfos struct {
	Infos []IFStateInfo
}

type IFStateInfo struct {
	IfID    uint64
	Active  bool
	RevInfo RevInfo
}
