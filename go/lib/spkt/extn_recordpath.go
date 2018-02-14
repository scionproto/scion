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
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

var _ common.Extension = (*RecordPath)(nil)

const (
	RecordPathEntryLen = 8
)

type RecordPath struct {
	Hops []*RecordPathEntry
}

func NewRecordPath(totalHops int) *RecordPath {
	t := &RecordPath{}
	t.Hops = make([]*RecordPathEntry, 0, totalHops)
	return t
}

func (t *RecordPath) NumHops() int {
	return len(t.Hops)
}

func (t *RecordPath) TotalHops() int {
	return int(cap(t.Hops))
}

func (t *RecordPath) Write(b common.RawBytes) error {
	if len(b) < t.Len() {
		return common.NewBasicError("Buffer too short", nil, "method", "RecordPath.Write")
	}
	b[0] = uint8(t.NumHops())
	offset := common.ExtnSubHdrLen
	for _, h := range t.Hops {
		h.Write(b[offset:])
		offset += RecordPathEntryLen
	}
	return nil
}

func (t *RecordPath) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, t.Len())
	if err := t.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (t *RecordPath) Copy() common.Extension {
	c := NewRecordPath(t.TotalHops())
	for _, h := range t.Hops {
		c.Hops = append(c.Hops, h.Copy())
	}
	return c
}

func (t *RecordPath) Reverse() (bool, error) {
	// Nothing to do.
	return true, nil
}

func (t *RecordPath) Len() int {
	return common.ExtnFirstLineLen + t.TotalHops()*common.LineLen
}

func (t *RecordPath) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (t *RecordPath) Type() common.ExtnType {
	return common.ExtnRecordPathType
}

func (t *RecordPath) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "RecordPath (%dB): Hops filled/total: %d/%d\n",
		t.Len(), t.NumHops(), t.TotalHops())
	for i, h := range t.Hops {
		fmt.Fprintf(buf, "  %d. %v\n", i, h)
	}
	return buf.String()
}

type RecordPathEntry struct {
	IA        addr.IA
	IfID      uint16
	TimeStamp uint16
}

func (t *RecordPathEntry) Copy() *RecordPathEntry {
	return &RecordPathEntry{IA: t.IA, IfID: t.IfID, TimeStamp: t.TimeStamp}
}

func (t *RecordPathEntry) Write(b common.RawBytes) {
	offset := 0
	t.IA.Write(b[offset:])
	offset += addr.IABytes
	common.Order.PutUint16(b[offset:], t.IfID)
	offset += 2
	common.Order.PutUint16(b[offset:], t.TimeStamp)
}
