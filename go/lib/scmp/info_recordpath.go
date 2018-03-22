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
	"bytes"
	"fmt"
	"time"

	//log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// Record Path Entry format:
//
//  0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                                  IA                                   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                                 IfID                                  |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                TS                 |               Unused              |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
// TS is the time since SCMP Timestamp in microseconds, truncated to 32bits.
//
const (
	recordPathEntryLen = addr.IABytes + 4 + common.IFIDBytes
)

type RecordPathEntry struct {
	IA   addr.IA
	IfID common.IFIDType
	TS   uint32
}

func (entry *RecordPathEntry) write(b common.RawBytes) {
	entry.IA.Write(b)
	offset := addr.IABytes
	common.Order.PutUint64(b[offset:], uint64(entry.IfID))
	offset += 8
	common.Order.PutUint32(b[offset:], entry.TS)
}

func (entry *RecordPathEntry) read(b common.RawBytes) {
	entry.IA = addr.IAFromRaw(b)
	offset := addr.IABytes
	entry.IfID = common.IFIDType(common.Order.Uint64(b[offset:]))
	offset += 8
	entry.TS = common.Order.Uint32(b[offset:])
}

func (entry *RecordPathEntry) String() string {
	return fmt.Sprintf("IA: %s, IfID: %d, TimeOff: %s", entry.IA, entry.IfID,
		time.Duration(entry.TS)*time.Microsecond)
}

// Record Path packet format:
//
//  0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                                   Id                                  |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |NumHops |                            Unused                            |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                           RecordPathEntry[0]                          |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// .                                   .                                   .
// .                                   .                                   .
// .                                   .                                   .
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                           RecordPathEntry[n]                          |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
var _ Info = (*InfoRecordPath)(nil)

const (
	recordPathHdrLen = 16
)

type InfoRecordPath struct {
	Id      uint64
	Entries []*RecordPathEntry
}

func InfoRecordPathFromRaw(b common.RawBytes) (*InfoRecordPath, error) {
	if len(b) < recordPathHdrLen {
		return nil, common.NewBasicError("Truncated RecordPath info header", nil,
			"min", recordPathHdrLen, "actual", len(b))
	}
	rec := &InfoRecordPath{}
	rec.Id = common.Order.Uint64(b[:8])
	numHops := int(b[8])
	// Skip header
	if len(b[recordPathHdrLen:])%recordPathEntryLen != 0 {
		return nil, common.NewBasicError("Illegal RecordPath info entries length", nil,
			"len", len(b[recordPathHdrLen:]), "entryLen", recordPathEntryLen)
	}
	maxHops := len(b[recordPathHdrLen:]) / recordPathEntryLen
	if numHops > maxHops {
		return nil, common.NewBasicError("Invalid header", nil, "NumHops", numHops,
			"MaxHops", maxHops)
	}
	rec.Entries = make([]*RecordPathEntry, numHops, maxHops)
	offset := recordPathHdrLen
	for i := 0; i < numHops; i++ {
		e := &RecordPathEntry{}
		e.read(b[offset:])
		rec.Entries[i] = e
		offset += recordPathEntryLen
	}
	return rec, nil
}

func (rec *InfoRecordPath) Copy() Info {
	r := &InfoRecordPath{Id: rec.Id}
	r.Entries = make([]*RecordPathEntry, rec.NumHops(), rec.TotalHops())
	for i, e := range rec.Entries {
		r.Entries[i] = &RecordPathEntry{IA: e.IA, TS: e.TS, IfID: e.IfID}
	}
	return r
}

func (rec *InfoRecordPath) NumHops() int {
	return len(rec.Entries)
}

func (rec *InfoRecordPath) TotalHops() int {
	return cap(rec.Entries)
}

func (rec *InfoRecordPath) Len() int {
	return recordPathHdrLen + rec.TotalHops()*recordPathEntryLen
}

func (rec *InfoRecordPath) Write(b common.RawBytes) (int, error) {
	if len(b) < rec.Len() {
		return 0, common.NewBasicError("Not enough space in buffer", nil,
			"Expected", rec.Len(), "Actual", len(b))
	}
	common.Order.PutUint64(b[0:8], rec.Id)
	b[8] = uint8(rec.NumHops())
	offset := recordPathHdrLen
	for _, e := range rec.Entries {
		e.write(b[offset:])
		offset += recordPathEntryLen
	}
	if offset < rec.Len() {
		b[offset:].Zero()
	}
	return rec.Len(), nil
}

func (rec *InfoRecordPath) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "RecordPath Id 0x%016x: Hops filled/total: %d/%d\n",
		rec.Id, rec.NumHops(), rec.TotalHops())
	for i, e := range rec.Entries {
		fmt.Fprintf(buf, " %2d. %s\n", i+1, e.String())
	}
	return buf.String()
}
