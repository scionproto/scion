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

package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"

	log "github.com/inconshreveable/log15"
	"gopkg.in/restruct.v1"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

var _ Extension = (*Traceroute)(nil)

type Traceroute struct {
	data      []uint8
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

var ErrorLenMultiple = fmt.Sprintf("Header length isn't a multiple of %dB", spkt.LineLen)

func TracerouteFromRaw(b []byte, logger log.Logger) (*Traceroute, *util.Error) {
	t := &Traceroute{data: b}
	// Index past ext subheader:
	t.NumHops = t.data[3]
	// Ignore subheader line:
	t.TotalHops = uint8(len(t.data)/spkt.LineLen) - 1
	t.Logger = logger.New("ext", "traceroute")
	t.Debug("Traceroute extension found", "len", len(b), "numHops", t.NumHops,
		"totalHops", t.TotalHops)
	return t, nil
}

func (t *Traceroute) Add(entry *TracerouteEntry) *util.Error {
	if t.NumHops == t.TotalHops {
		return util.NewError(ErrorHdrFull, log.Ctx{"entries": t.NumHops})
	}
	t.NumHops += 1
	offset := spkt.LineLen * t.NumHops
	out, err := restruct.Pack(binary.BigEndian, entry)
	if err != nil {
		return util.NewError(ErrorPack, "err", err)
	}
	copy(t.data[offset:], out)
	return nil
}

func (t *Traceroute) Entry(idx int) (*TracerouteEntry, *util.Error) {
	if idx > int(t.NumHops-1) {
		return nil, util.NewError(ErrorIdx, "idx", idx, "max", t.NumHops-1)
	}
	entry := TracerouteEntry{}
	offset := spkt.LineLen * (idx + 1)
	if err := restruct.Unpack(t.data[offset:], binary.BigEndian, &entry); err != nil {
		return nil, util.NewError(ErrorUnpack, "idx", idx, "err", err)
	}
	return &entry, nil
}

func (t *Traceroute) RegisterHooks(h *Hooks) *util.Error {
	h.Validate = append(h.Validate, t.Validate)
	h.Process = append(h.Process, t.Process)
	return nil
}

func (t *Traceroute) Validate() (HookResult, *util.Error) {
	if len(t.data)%spkt.LineLen != 0 {
		return HookError, util.NewError(ErrorLenMultiple, "len", len(t.data))
	}
	if t.NumHops > t.TotalHops {
		return HookError, util.NewError(ErrorTooManyEntries,
			"max", t.TotalHops, "actual", t.NumHops)
	}
	return HookContinue, nil
}

func (t *Traceroute) Process() (HookResult, *util.Error) {
	// FIXME(kormat): finish implementing this.
	/*
		if err := t.Add(localIA,...); err != nil {
			t.Error("Unable to add entry", err)
		}
	*/
	return HookContinue, nil
}

func (t *Traceroute) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Traceroute (%dB): Hops filled/total: %d/%d\n",
		len(t.data), t.NumHops, t.TotalHops)
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
