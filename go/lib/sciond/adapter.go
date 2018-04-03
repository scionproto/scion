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

package sciond

import (
	"strconv"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/proto"
)

var _ disp.MessageAdapter = (*Adapter)(nil)

type Adapter struct{}

func (a *Adapter) MsgToRaw(msg proto.Cerealizable) (common.RawBytes, error) {
	sciondMsg := msg.(*Pld)
	return proto.PackRoot(sciondMsg)
}

func (a *Adapter) RawToMsg(b common.RawBytes) (proto.Cerealizable, error) {
	return NewPldFromRaw(b)
}

func (a *Adapter) MsgKey(msg proto.Cerealizable) string {
	sciondMsg := msg.(*Pld)
	return strconv.FormatUint(sciondMsg.Id, 10)
}
