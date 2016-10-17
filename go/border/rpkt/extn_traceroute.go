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
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

var _ RExtension = (*RTraceroute)(nil)

type RTraceroute struct {
	rp        *RtrPkt
	raw       common.RawBytes
	NumHops   uint8
	TotalHops uint8
	log.Logger
}

const (
	ErrorHdrFull        = "Header already full"
	ErrorPack           = "Packing failed"
	ErrorUnpack         = "Unpacking failed"
	ErrorIdx            = "Entry index out of range"
	ErrorTooManyEntries = "Header claims too many entries"
)

var ErrorLenMultiple = fmt.Sprintf("Header length isn't a multiple of %dB", common.LineLen)

func RTracerouteFromRaw(rp *RtrPkt, start, end int) (*RTraceroute, *common.Error) {
	t := &RTraceroute{rp: rp, raw: rp.Raw[start:end]}
	t.NumHops = t.raw[0]
	// Ignore subheader line
	t.TotalHops = uint8(len(t.raw)-common.ExtnSubHdrLen) / common.LineLen
	t.Logger = rp.Logger.New("ext", "traceroute")
	return t, nil
}

func (t *RTraceroute) Add(entry *spkt.TracerouteEntry) *common.Error {
	if t.NumHops == t.TotalHops {
		return common.NewError(ErrorHdrFull, log.Ctx{"entries": t.NumHops})
	}
	t.NumHops += 1
	offset := common.LineLen * t.NumHops
	entry.IA.Write(t.raw[offset:])
	offset += addr.IABytes
	common.Order.PutUint16(t.raw[offset:], entry.IfID)
	offset += 2
	common.Order.PutUint16(t.raw[offset:], entry.TimeStamp)
	return nil
}

func (t *RTraceroute) Entry(idx int) (*spkt.TracerouteEntry, *common.Error) {
	if idx > int(t.NumHops-1) {
		return nil, common.NewError(ErrorIdx, "idx", idx, "max", t.NumHops-1)
	}
	entry := spkt.TracerouteEntry{}
	offset := common.LineLen * (idx + 1)
	entry.IA = *addr.IAFromRaw(t.raw[offset:])
	offset += addr.IABytes
	entry.IfID = common.Order.Uint16(t.raw[offset:])
	offset += 2
	entry.TimeStamp = common.Order.Uint16(t.raw[offset:])
	return &entry, nil
}

func (t *RTraceroute) RegisterHooks(h *Hooks) *common.Error {
	h.Validate = append(h.Validate, t.Validate)
	h.Process = append(h.Process, t.Process)
	return nil
}

func (t *RTraceroute) Validate() (HookResult, *common.Error) {
	if (len(t.raw)-common.ExtnFirstLineLen)%common.LineLen != 0 {
		return HookError, common.NewError(ErrorLenMultiple, "len", len(t.raw))
	}
	if t.NumHops > t.TotalHops {
		return HookError, common.NewError(ErrorTooManyEntries,
			"max", t.TotalHops, "actual", t.NumHops)
	}
	return HookContinue, nil
}

func (t *RTraceroute) Process() (HookResult, *common.Error) {
	ts := (time.Now().UnixNano() / 1000) % (1 << 16)
	entry := spkt.TracerouteEntry{
		IA: *conf.C.IA, IfID: uint16(*t.rp.ifCurr), TimeStamp: uint16(ts),
	}
	if err := t.Add(&entry); err != nil {
		t.Error("Unable to add entry", err)
	}
	t.raw[3] = t.NumHops
	return HookContinue, nil
}

func (t *RTraceroute) GetExtn() (common.Extension, *common.Error) {
	s := spkt.NewTraceroute(int(t.TotalHops))
	for i := 0; i < int(t.NumHops); i++ {
		entry, err := t.Entry(i)
		if err != nil {
			return nil, err
		}
		s.Hops = append(s.Hops, entry)
	}
	return s, nil
}

func (t *RTraceroute) Len() int {
	return len(t.raw)
}

func (t *RTraceroute) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (t *RTraceroute) Type() common.ExtnType {
	return common.ExtnTracerouteType
}

func (t *RTraceroute) String() string {
	// Delegate string representation to spkt.Traceroute
	e, err := t.GetExtn()
	if err != nil {
		return fmt.Sprintf("Traceroute - %v: %v", err.Desc, err.String())
	}
	return e.String()
}
