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

package messenger

import (
	"strconv"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/proto"
)

var _ disp.MessageAdapter = (*Adapter)(nil)

// Adapter implements disp.MessageAdapter for ctrl.SignedPld.
type Adapter struct{}

// Default adapter
var DefaultAdapter = &Adapter{}

func (a *Adapter) MsgToRaw(msg proto.Cerealizable) (common.RawBytes, error) {
	pld, ok := msg.(*ctrl.SignedPld)
	if !ok {
		return nil, common.NewBasicError(
			"Unable to type assert proto.Cerealizable to ctrl.SignedPld",
			nil, "msg", msg, "type", common.TypeOf(msg))
	}
	return pld.PackPld()
}

func (a *Adapter) RawToMsg(b common.RawBytes) (proto.Cerealizable, error) {
	return ctrl.NewSignedPldFromRaw(b)
}

func (a *Adapter) MsgKey(msg proto.Cerealizable) string {
	signedCtrlPld, ok := msg.(*ctrl.SignedPld)
	if !ok {
		// FIXME(scrye): Change interface to handle key errors instead of
		// logging it here
		log.Warn("Unable to type assert disp.Message to ctrl.SignedPld", "msg", msg,
			"type", common.TypeOf(msg))
		return ""
	}

	// XXX(scrye): For request/response matching based on ID, verification is
	// not taken into account. This allows attackers to change the ID in a
	// response to make it match any outstanding request.
	ctrlPld, err := signedCtrlPld.Pld()
	if err != nil {
		log.Warn("Unable to extract CtrlPld from SignedCtrlPld", "err", err)
		return ""
	}
	return strconv.FormatUint(ctrlPld.ReqId, 10)
}
