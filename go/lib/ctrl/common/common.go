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

package common

import (
	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

type CtrlPld interface {
	common.Payload
	CtrlWrite(*proto.SCION) *common.Error
	PldClass() proto.SCION_Which
}

func WritePld(b common.RawBytes, ctrlWrite func(*proto.SCION) *common.Error) (int, *common.Error) {
	scion, err := proto.NewSCIONMsg()
	if err != nil {
		return 0, err
	}
	if err := ctrlWrite(scion); err != nil {
		return 0, err
	}
	raw := &util.Raw{B: b, Offset: 4}
	enc := capnp.NewPackedEncoder(raw)
	if err := enc.Encode(scion.Segment().Message()); err != nil {
		return 0, common.NewError("Ctrl payload encoding failed", "err", err)
	}
	// Set payload length
	common.Order.PutUint32(b, uint32(raw.Offset-4))
	return raw.Offset, nil
}
