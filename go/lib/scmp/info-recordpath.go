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

	//log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// Record Path Entry format:
//
//  0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                IA                 |      IfID       |   Timestamp     |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
const (
	RecordPathEntryLen = 8
)

type RecordPathEntry struct {
	IA        addr.IA
	IfID      uint16
	TimeStamp uint16
}

func (t *RecordPathEntry) Copy() *RecordPathEntry {
	return &RecordPathEntry{IA: t.IA, IfID: t.IfID, TimeStamp: t.TimeStamp}
}

func (entry *RecordPathEntry) Write(b common.RawBytes) {
	offset := 0
	entry.IA.Write(b[offset:])
	offset += addr.IABytes
	common.Order.PutUint16(b[offset:], entry.IfID)
	offset += 2
	common.Order.PutUint16(b[offset:], entry.TimeStamp)
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
	RecordPathHdrLen = 16
)

type InfoRecordPath struct {
	Id      uint64
	NumHops uint8
	MaxHops uint8
	raw     common.RawBytes
}

func InfoRecordPathFromRaw(b common.RawBytes) (*InfoRecordPath, error) {
	rec := &InfoRecordPath{}
	rec.Id = common.Order.Uint64(b[0:8])
	rec.NumHops = b[8]
	// Skip first 8 Bytes [Id | NumHops]
	rec.MaxHops = uint8((len(b) / common.LineLen) - 1)
	if !(rec.NumHops <= rec.MaxHops) {
		return nil, common.NewBasicError("Invalid header", nil, "NumHops", rec.NumHops,
			"MaxHops", rec.MaxHops)
	}
	rec.raw = b
	return rec, nil
}

// Add creates a new record path entry directly to the underlying buffer.
func (rec *InfoRecordPath) Add(entry *RecordPathEntry) error {
	if rec.NumHops == rec.MaxHops {
		return common.NewBasicError("Header already full", nil, "entries", rec.NumHops)
	}
	offset := RecordPathHdrLen + common.LineLen*rec.NumHops
	entry.Write(rec.raw[offset:])
	rec.NumHops += 1
	rec.raw[8] = rec.NumHops
	return nil
}

func (rec *InfoRecordPath) Copy() Info {
	r := InfoRecordPath{Id: rec.Id, NumHops: rec.NumHops, MaxHops: rec.MaxHops}
	r.raw = make([]byte, len(rec.raw))
	copy(r.raw, rec.raw)
	return &r
}

func (rec *InfoRecordPath) Len() int {
	return RecordPathHdrLen + int(rec.MaxHops)*RecordPathEntryLen
}

func (rec *InfoRecordPath) Write(b common.RawBytes) (int, error) {
	var l int
	if rec.raw == nil {
		l = rec.Len()
	} else {
		l = len(rec.raw)
	}
	if len(b) < l {
		return 0, common.NewBasicError("Not enough space in buffer", nil,
			"InfoRecordPathLen", l, "BufferLen", len(b))
	}
	if rec.raw == nil {
		common.Order.PutUint64(b[0:8], rec.Id)
		b[8] = rec.NumHops
	} else {
		copy(b, rec.raw)
	}
	return l, nil
}

// Entry parses a specified traceroute entry from the underlying buffer.
func (rec *InfoRecordPath) Entry(idx int) *RecordPathEntry {
	entry := RecordPathEntry{}
	offset := RecordPathHdrLen + common.LineLen*idx
	entry.IA = addr.IAFromRaw(rec.raw[offset:])
	offset += addr.IABytes
	entry.IfID = common.Order.Uint16(rec.raw[offset:])
	offset += 2
	entry.TimeStamp = common.Order.Uint16(rec.raw[offset:])
	return &entry
}

func (rec *InfoRecordPath) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "RecordPath Id %d: Hops filled/total: %d/%d\n",
		rec.Id, rec.NumHops, rec.MaxHops)
	for i := 0; i < int(rec.NumHops); i++ {
		e := rec.Entry(i)
		fmt.Fprintf(buf, "  %d. %v %v %v\n", i, e.IA, e.IfID, e.TimeStamp)
	}
	return buf.String()
}
