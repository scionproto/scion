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
	"github.com/netsec-ethz/scion/go/lib/common"
	ctrl_cmn "github.com/netsec-ethz/scion/go/lib/ctrl/common"
	"github.com/netsec-ethz/scion/go/proto"
)

type PathMgmtPld interface {
	ctrl_cmn.CtrlPld
	PathMgmtWrite(*proto.PathMgmt) *common.Error
	PldType() proto.PathMgmt_Which
}

func NewPathMgmtPldFromProto(msg proto.PathMgmt) (PathMgmtPld, *common.Error) {
	switch msg.Which() {
	case proto.PathMgmt_Which_segReq:
		m, _ := msg.SegReq()
		return NewSegReqFromProto(m)
	case proto.PathMgmt_Which_segReply:
		m, _ := msg.SegReply()
		return NewSegRecsFromProto(m, proto.PathMgmt_Which_segReply)
	case proto.PathMgmt_Which_segReg:
		m, _ := msg.SegReg()
		return NewSegRecsFromProto(m, proto.PathMgmt_Which_segReg)
	case proto.PathMgmt_Which_segSync:
		m, _ := msg.SegSync()
		return NewSegRecsFromProto(m, proto.PathMgmt_Which_segSync)
	case proto.PathMgmt_Which_revInfo:
		m, _ := msg.RevInfo()
		return NewRevInfoFromProto(m)
	case proto.PathMgmt_Which_ifStateReq:
		m, _ := msg.IfStateReq()
		return NewIFStateReqFromProto(m)
	case proto.PathMgmt_Which_ifStateInfos:
		m, _ := msg.IfStateInfos()
		return NewIFStateInfosFromProto(m)
	}
	return nil, common.NewError("Unknown or unsupported PathMgmt type", "type", msg.Which())
}
