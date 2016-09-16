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

package scmp

import (
	"fmt"
	"time"

	//log "github.com/inconshreveable/log15"
	"gopkg.in/restruct.v1"

	"github.com/netsec-ethz/scion/go/lib/libscion"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	HdrLen = 16
)

const (
	ErrorSCMPHdrUnpack = "Failed to unpack SCMP header"
)

type Hdr struct {
	Class     Class
	Type      Type
	Len       uint16
	Checksum  util.RawBytes `struct:"[2]byte"`
	Timestamp uint64        // Time in µs since unix epoch
}

func HdrFromRaw(b util.RawBytes) (*Hdr, *util.Error) {
	h := &Hdr{}
	if err := restruct.Unpack(b, order, h); err != nil {
		return nil, util.NewError(ErrorSCMPHdrUnpack, "err", err)
	}
	return h, nil
}

func (h *Hdr) Pack() (util.RawBytes, *util.Error) {
	out, err := restruct.Pack(order, h)
	if err != nil {
		return nil, util.NewError("Error packing SCMP header", "err", err)
	}
	return out, nil
}

func (h *Hdr) CalcChecksum(srcAddr, dstAddr, pld util.RawBytes) (util.RawBytes, *util.Error) {
	out := make([]byte, 2)
	hdr, err := h.Pack()
	if err != nil {
		return nil, err
	}
	// Zero checksum
	hdr[6] = 0
	hdr[7] = 0
	sum := libscion.Checksum(srcAddr, dstAddr, []byte{byte(spkt.L4SCMP)}, hdr, pld)
	order.PutUint16(out, sum)
	return out, nil
}

func (h *Hdr) String() string {
	secs := int64(h.Timestamp / 1000000)
	nanos := int64((h.Timestamp % 1000000) * 1000)
	return fmt.Sprintf("Class=%v Type=%v Len=%vB Checksum=%v Timestamp=%v",
		h.Class, h.Type.Name(h.Class), h.Len, h.Checksum, time.Unix(secs, nanos))
}
