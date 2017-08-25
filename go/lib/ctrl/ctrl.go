// Copyright 2016 ETH Zurich
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

package ctrl

import (
	"bytes"

	//log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	ctrl_cmn "github.com/netsec-ethz/scion/go/lib/ctrl/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/ifid"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/proto"
)

func NewCtrlPldFromRaw(b common.RawBytes) (ctrl_cmn.CtrlPld, *common.Error) {
	rawPld := b
	pldLen := common.Order.Uint32(rawPld)
	rawPld = rawPld[4:]
	if int(pldLen) != len(rawPld) {
		return nil, common.NewError("Ctrl payload length incorrect",
			"expected", pldLen, "actual", len(rawPld))
	}
	buf := bytes.NewBuffer(rawPld)
	msg, err := capnp.NewPackedDecoder(buf).Decode()
	if err != nil {
		return nil, common.NewError("Ctrl payload decoding failed", "err", err)
	}
	// Handle any panics while parsing
	defer func() *common.Error {
		if err := recover(); err != nil {
			return common.NewError("Ctrl payload parsing failed", "err", err)
		}
		return nil
	}()
	scion, err := proto.ReadRootSCION(msg)
	if err != nil {
		return nil, common.NewError("Ctrl payload decoding failed", "err", err)
	}
	switch scion.Which() {
	case proto.SCION_Which_ifid:
		m, _ := scion.Ifid()
		return ifid.NewIFIDFromProto(m)
	case proto.SCION_Which_pathMgmt:
		m, _ := scion.PathMgmt()
		return path_mgmt.NewPathMgmtPldFromProto(m)
	case proto.SCION_Which_pcb:
		m, _ := scion.Pcb()
		return seg.NewPathSegmentFromProto(m)
	}
	return nil, common.NewError("Unknown or unsupported CtrlPld type", "type", scion.Which())
}
