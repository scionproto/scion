// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package spath

import (
	"fmt"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	InfoFieldLength    = common.LineLen
	ErrorInfoFTooShort = "InfoF too short"
)

// Info Field format:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |r r r r r P S C|                  Timestamp ...                |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      ...      |              ISD              |     Hops      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type InfoField struct {
	// Previously Up, ConsDir = !Up
	ConsDir  bool
	Shortcut bool
	Peer     bool
	// TsInt is the timestamp that denotes when the propagation of a path segment started.
	// Use Timestamp() to get a time.Time value.
	TsInt uint32
	// ISD denotes the origin ISD of a path segment.
	ISD  uint16
	Hops uint8
}

func InfoFFromRaw(b []byte) (*InfoField, error) {
	if len(b) < InfoFieldLength {
		return nil, common.NewBasicError(ErrorInfoFTooShort, nil,
			"min", InfoFieldLength, "actual", len(b))
	}
	inf := &InfoField{}
	flags := b[0]
	inf.ConsDir = flags&0x1 != 0
	inf.Shortcut = flags&0x2 != 0
	inf.Peer = flags&0x4 != 0
	offset := 1
	inf.TsInt = common.Order.Uint32(b[offset:])
	offset += 4
	inf.ISD = common.Order.Uint16(b[offset:])
	offset += 2
	inf.Hops = b[offset]
	return inf, nil
}

func (inf *InfoField) Write(b common.RawBytes) {
	b[0] = 0
	if inf.ConsDir {
		b[0] |= 0x1
	}
	if inf.Shortcut {
		b[0] |= 0x2
	}
	if inf.Peer {
		b[0] |= 0x4
	}
	offset := 1
	common.Order.PutUint32(b[offset:], inf.TsInt)
	offset += 4
	common.Order.PutUint16(b[offset:], inf.ISD)
	offset += 2
	b[offset] = inf.Hops
}

func (inf *InfoField) String() string {
	return fmt.Sprintf("ISD: %v TS: %v Hops: %v ConsDir: %v Shortcut: %v Peer: %v",
		inf.ISD, inf.Timestamp(), inf.Hops, inf.ConsDir, inf.Shortcut, inf.Peer)
}

// Timestamp returns TsInt as a time.Time.
func (inf *InfoField) Timestamp() time.Time {
	return time.Unix(int64(inf.TsInt), 0)
}

// WriteTo implements the io.WriterTo interface.
func (inf *InfoField) WriteTo(w io.Writer) (int64, error) {
	b := make(common.RawBytes, common.LineLen)
	inf.Write(b)
	n, err := w.Write(b)
	return int64(n), err
}
