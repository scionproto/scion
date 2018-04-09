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

package scmp

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

// Trace Route packet format:
//
//  0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                                  Id                                   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                                  IA                                   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                                 IfID                                  |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | HopOff |   In   |                       Unused                        |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
// The Requester should fill the ID, HopOff and In.
// When a BR process a TraceRoute REQUEST, it checks whether the HopOff matches
// the common header HopOff and its current interface is the Ingress/Egress
// (In is true for Ingress). In such a case the BR generates a REPLY filling
// the IA and IfID fields.
//
var _ Info = (*InfoTraceRoute)(nil)

const (
	traceRouteLen = 26
)

type InfoTraceRoute struct {
	Id     uint64
	IA     addr.IA
	IfID   common.IFIDType
	HopOff uint8
	In     bool
}

func InfoTraceRouteFromRaw(b common.RawBytes) (*InfoTraceRoute, error) {
	e := &InfoTraceRoute{}
	e.Id = common.Order.Uint64(b)
	e.IA = addr.IAFromRaw(b[8:])
	e.IfID = common.IFIDType(common.Order.Uint64(b[16:]))
	e.HopOff = b[24]
	e.In = b[25] == 1
	return e, nil
}

func (e *InfoTraceRoute) Copy() Info {
	return &InfoTraceRoute{Id: e.Id, IfID: e.IfID, IA: e.IA, HopOff: e.HopOff, In: e.In}
}

func (e *InfoTraceRoute) Len() int {
	return traceRouteLen + util.CalcPadding(traceRouteLen, common.LineLen)
}

func (e *InfoTraceRoute) Write(b common.RawBytes) (int, error) {
	common.Order.PutUint64(b, e.Id)
	e.IA.Write(b[8:])
	common.Order.PutUint64(b[16:], uint64(e.IfID))
	b[24] = e.HopOff
	if e.In {
		b[25] = 1
	} else {
		b[25] = 0
	}
	return util.FillPadding(b, traceRouteLen, common.LineLen), nil
}

func (e *InfoTraceRoute) String() string {
	return fmt.Sprintf("Id=0x%016x HopOff=%d In=%t IA=%s IfID=%d",
		e.Id, e.HopOff, e.In, e.IA, e.IfID)
}
