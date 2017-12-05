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

// This file contains the router's representation of the Traceroute hop-by-hop
// extension.

package rpkt

import (
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spkt"
)

var _ rExtension = (*rTraceroute)(nil)

// rTraceroute is the router's representation of the Traceroute extension.
type rTraceroute struct {
	rp        *RtrPkt
	raw       common.RawBytes
	NumHops   uint8
	TotalHops uint8
	log.Logger
}

var errLenMultiple = fmt.Sprintf("Header length isn't a multiple of %dB", common.LineLen)

// rTracerouteFromRaw creates an rTraceroute instance from raw bytes, keeping a
// reference to the location in the packet's buffer.
func rTracerouteFromRaw(rp *RtrPkt, start, end int) (*rTraceroute, error) {
	t := &rTraceroute{rp: rp, raw: rp.Raw[start:end]}
	t.NumHops = t.raw[0]
	// Ignore subheader line
	t.TotalHops = uint8((len(t.raw) - common.ExtnFirstLineLen) / common.LineLen)
	t.Logger = rp.Logger.New("ext", "traceroute")
	return t, nil
}

// Add creates a new traceroute entry directly to the underlying buffer.
func (t *rTraceroute) Add(entry *spkt.TracerouteEntry) error {
	if t.NumHops == t.TotalHops {
		return common.NewCError("Header already full", "entries", t.NumHops)
	}
	offset := common.ExtnFirstLineLen + common.LineLen*int(t.NumHops)
	entry.IA.Write(t.raw[offset:])
	offset += addr.IABytes
	common.Order.PutUint16(t.raw[offset:], entry.IfID)
	offset += 2
	common.Order.PutUint16(t.raw[offset:], entry.TimeStamp)
	t.NumHops += 1
	return nil
}

// Entry parses a specified traceroute entry from the underlying buffer.
func (t *rTraceroute) Entry(idx int) (*spkt.TracerouteEntry, error) {
	if idx > int(t.NumHops-1) {
		return nil, common.NewCError("Entry index out of range", "idx", idx, "max", t.NumHops-1)
	}
	entry := spkt.TracerouteEntry{}
	offset := common.ExtnFirstLineLen + common.LineLen*idx
	entry.IA = *addr.IAFromRaw(t.raw[offset:])
	offset += addr.IABytes
	entry.IfID = common.Order.Uint16(t.raw[offset:])
	offset += 2
	entry.TimeStamp = common.Order.Uint16(t.raw[offset:])
	return &entry, nil
}

func (t *rTraceroute) RegisterHooks(h *hooks) error {
	h.Validate = append(h.Validate, t.Validate)
	h.Process = append(h.Process, t.Process)
	return nil
}

func (t *rTraceroute) Validate() (HookResult, error) {
	if (len(t.raw)-common.ExtnFirstLineLen)%common.LineLen != 0 {
		return HookError, common.NewCError(errLenMultiple, "len", len(t.raw))
	}
	if t.NumHops > t.TotalHops {
		return HookError, common.NewCError("Header claims too many entries",
			"max", t.TotalHops, "actual", t.NumHops)
	}
	return HookContinue, nil
}

// Process creates a new entry, and adds it to the underlying buffer.
func (t *rTraceroute) Process() (HookResult, error) {
	// Take the current time in milliseconds, and truncate it to 16bits.
	ts := (time.Now().UnixNano() / 1000) % (1 << 16)
	entry := spkt.TracerouteEntry{
		IA: *t.rp.Ctx.Conf.IA, IfID: uint16(*t.rp.ifCurr), TimeStamp: uint16(ts),
	}
	if err := t.Add(&entry); err != nil {
		cerr := err.(*common.CError)
		cerr.Ctx = append(cerr.Ctx, "raw", t.rp.Raw)
		t.Error("Unable to add entry", "err", cerr)
	}
	// Update the raw buffer with the number of hops.
	t.raw[0] = t.NumHops
	return HookContinue, nil
}

// GetExtn returns the spkt.Traceroute representation. The big difference
// between the two representations is that the latter doesn't have an
// underlying buffer, so instead it has a slice of TracerouteEntry's.
func (t *rTraceroute) GetExtn() (common.Extension, error) {
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

func (t *rTraceroute) Len() int {
	return len(t.raw)
}

func (t *rTraceroute) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (t *rTraceroute) Type() common.ExtnType {
	return common.ExtnTracerouteType
}

func (t *rTraceroute) String() string {
	// Delegate string representation to spkt.Traceroute
	e, err := t.GetExtn()
	if err != nil {
		return fmt.Sprintf("Traceroute: %v", err)
	}
	return e.String()
}
