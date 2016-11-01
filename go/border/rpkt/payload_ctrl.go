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

package rpkt

import (
	"bytes"

	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

func (rp *RPkt) parseCtrlPayload() (HookResult, interface{}, *util.Error) {
	if rp.L4Type != common.L4UDP {
		return HookContinue, nil, nil
	}
	rawPld := rp.Raw[rp.idxs.pld:]
	pldLen := order.Uint32(rawPld)
	rawPld = rawPld[4:]
	if int(pldLen) != len(rawPld) {
		return HookError, nil, util.NewError(ErrorPayloadLenWrong,
			"expected", pldLen, "actual", len(rawPld))
	}
	buf := bytes.NewBuffer(rawPld)
	msg, err := capnp.NewPackedDecoder(buf).Decode()
	if err != nil {
		return HookError, nil, util.NewError(ErrorPayloadDecode, "err", err)
	}
	// Handle any panics while parsing
	defer func() *util.Error {
		if err := recover(); err != nil {
			return util.NewError(ErrorPayloadParse, "err", err)
		}
		return nil
	}()
	pld, err := proto.ReadRootSCION(msg)
	if err != nil {
		return HookError, nil, util.NewError(ErrorPayloadParse, "err", err)
	}
	return HookFinish, &pld, nil
}

func (rp *RPkt) updateCtrlPld() *util.Error {
	// First remove old payload, if any
	rp.Raw = rp.Raw[:rp.idxs.pld]
	var buf bytes.Buffer
	// Reserve space for length
	buf.Write(make([]byte, 4))
	enc := capnp.NewPackedEncoder(&buf)
	pld := rp.pld.(*proto.SCION)
	if err := enc.Encode(pld.Segment().Message()); err != nil {
		return util.NewError("Unable to encode ctrl payload", "err", err)
	}
	newPld := util.RawBytes(buf.Bytes())
	// Set payload length
	order.PutUint32(newPld, uint32(len(newPld)-4))
	// Append new payload
	rp.Raw = append(rp.Raw, newPld...)
	// Now start updating headers
	if err := rp.updateL4(); err != nil {
		return err
	}
	rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
	rp.CmnHdr.Write(rp.Raw)
	return nil
}
