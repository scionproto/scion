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

package spkt

import (
	"bytes"

	//log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*CtrlPld)(nil)

type CtrlPld struct {
	*proto.SCION
}

func NewCtrlPldFromRaw(b common.RawBytes) (*CtrlPld, *common.Error) {
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
	pld, err := proto.ReadRootSCION(msg)
	if err != nil {
		return nil, common.NewError("Ctrl payload parsing failed", "err", err)
	}
	return &CtrlPld{SCION: &pld}, nil
}

func (c *CtrlPld) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (c *CtrlPld) Copy() (common.Payload, *common.Error) {
	rawPld, err := c.Pack()
	if err != nil {
		return nil, err
	}
	return NewCtrlPldFromRaw(rawPld)
}

func (c *CtrlPld) Write(b common.RawBytes) (int, *common.Error) {
	raw := &util.Raw{B: b, Offset: 4}
	enc := capnp.NewPackedEncoder(raw)
	if err := enc.Encode(c.SCION.Segment().Message()); err != nil {
		return 0, common.NewError("Ctrl payload encoding failed", "err", err)
	}
	// Set payload length
	common.Order.PutUint32(b, uint32(raw.Offset-4))
	return raw.Offset, nil
}

func (c *CtrlPld) Pack() (common.RawBytes, *common.Error) {
	buf := bytes.NewBuffer(make(common.RawBytes, 4))
	enc := capnp.NewPackedEncoder(buf)
	if err := enc.Encode(c.SCION.Segment().Message()); err != nil {
		return nil, common.NewError("Ctrl payload encoding failed", "err", err)
	}
	rawPld := buf.Bytes()
	// Set payload length
	common.Order.PutUint32(rawPld, uint32(len(rawPld)-4))
	return rawPld, nil
}
