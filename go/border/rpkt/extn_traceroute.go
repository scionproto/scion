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
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

var _ Extension = (*Traceroute)(nil)

type Traceroute struct {
	rp        *RPkt
	raw       util.RawBytes
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

func TracerouteFromRaw(rp *RPkt, start, end int) (*Traceroute, *util.Error) {
	t := &Traceroute{rp: rp, raw: rp.Raw[start:end]}
	// Index past ext subheader:
	t.NumHops = t.raw[3]
	// Ignore subheader line:
	t.TotalHops = uint8(len(t.raw)/common.LineLen) - 1
	t.Logger = rp.Logger.New("ext", "traceroute")
	return t, nil
}

func (t *Traceroute) Add(entry *TracerouteEntry) *util.Error {
	if t.NumHops == t.TotalHops {
		return util.NewError(ErrorHdrFull, log.Ctx{"entries": t.NumHops})
	}
	t.NumHops += 1
	offset := common.LineLen * t.NumHops
	entry.IA.Write(t.raw[offset:])
	offset += addr.IABytes
	order.PutUint16(t.raw[offset:], entry.IfID)
	offset += 2
	order.PutUint16(t.raw[offset:], entry.TimeStamp)
	return nil
}

func (t *Traceroute) Entry(idx int) (*TracerouteEntry, *util.Error) {
	if idx > int(t.NumHops-1) {
		return nil, util.NewError(ErrorIdx, "idx", idx, "max", t.NumHops-1)
	}
	entry := TracerouteEntry{}
	offset := common.LineLen * (idx + 1)
	entry.IA = *addr.IAFromRaw(t.raw[offset:])
	offset += addr.IABytes
	entry.IfID = order.Uint16(t.raw[offset:])
	offset += 2
	entry.TimeStamp = order.Uint16(t.raw[offset:])
	return &entry, nil
}

func (t *Traceroute) RegisterHooks(h *Hooks) *util.Error {
	h.Validate = append(h.Validate, t.Validate)
	h.Process = append(h.Process, t.Process)
	return nil
}

func (t *Traceroute) Validate() (HookResult, *util.Error) {
	if len(t.raw)%common.LineLen != 0 {
		return HookError, util.NewError(ErrorLenMultiple, "len", len(t.raw))
	}
	if t.NumHops > t.TotalHops {
		return HookError, util.NewError(ErrorTooManyEntries,
			"max", t.TotalHops, "actual", t.NumHops)
	}
	return HookContinue, nil
}

func (t *Traceroute) Process() (HookResult, *util.Error) {
	ts := (time.Now().UnixNano() / 1000) % (1 << 16)
	entry := TracerouteEntry{*conf.C.IA, uint16(*t.rp.ifCurr), uint16(ts)}
	if err := t.Add(&entry); err != nil {
		t.Error("Unable to add entry", err)
	}
	t.raw[3] = t.NumHops
	return HookContinue, nil
}

func (t *Traceroute) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Traceroute (%dB): Hops filled/total: %d/%d\n",
		len(t.raw), t.NumHops, t.TotalHops)
	for i := 0; i < int(t.NumHops); i++ {
		entry, err := t.Entry(i)
		if err != nil {
			t.Error("Unable to retrieve entry", "idx", i, "err", err)
			fmt.Fprintf(buf, "ERROR")
			break
		}
		fmt.Fprintf(buf, "%s\n", entry)
	}
	return buf.String()
}

type TracerouteEntry struct {
	IA        addr.ISD_AS
	IfID      uint16
	TimeStamp uint16
}

func (t *TracerouteEntry) String() string {
	return fmt.Sprintf("IA: %s IfID: %v Timestamp: %v", t.IA, t.IfID, t.TimeStamp)
}
