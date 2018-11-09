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

// Package rpkt contains the router representation of a SCION packet.
//
// This differs from the higher-level github.com/scionproto/scion/go/lib/spkt
// package by being tied to an underlying buffer, which greatly improves
// processing performance at the expense of flexibility.
package rpkt

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

// pktBufSize is the maxiumum size of a packet buffer.
// FIXME(kormat): this should be reduced as soon as we respect the actual link MTU.
const pktBufSize = 9 * 1024

// callbacks is an anonymous struct used for functions supplied by the router
// for various processing tasks.
var callbacks struct {
	rawSRevF func(RawSRevCallbackArgs)
}

// Init takes callback functions provided by the router and stores them for use
// by the rpkt package.
func Init(rawSRevF func(RawSRevCallbackArgs)) {
	callbacks.rawSRevF = rawSRevF
}

// Router representation of SCION packet, including metadata.  The comments for the members have
// tags to specifiy if the member is set during receiving (RECV), parsing (PARSE), processing
// (PROCESS) or routing (ROUTE). A number of the non-exported fields are pointers, as they are
// either optional or computed only on demand.
type RtrPkt struct {
	// Id is a pseudo-random identifier for a packet, to allow correlation of logging statements.
	// (RECV)
	Id string
	// Raw is the underlying buffer that represents the raw packet bytes. (RECV)
	Raw common.RawBytes
	// TimeIn is the time the packet was received. This is used for metrics
	// calculations. (RECV)
	TimeIn time.Time
	// DirFrom is the direction from which the packet was received. (RECV)
	DirFrom rcmn.Dir
	// Ingress contains the incoming overlay metadata the packet arrived with, and the (list of)
	// interface(s) it arrived on. (RECV)
	Ingress addrIFPair
	// Egress is a list of function & address pairs that determine how and where to the packet will
	// be sent. (PROCESS/ROUTE)
	Egress []EgressPair
	// CmnHdr is the SCION common header. Required for every packet. (PARSE)
	CmnHdr spkt.CmnHdr
	// Flag to indicate whether this router incremented the path. (ROUTE)
	IncrementedPath bool
	// idxs contains a set of indexes into Raw which point to the start of certain sections of the
	// packet. (PARSE)
	idxs packetIdxs
	// dstIA is the destination ISD-AS. (PARSE)
	dstIA addr.IA
	// srcIA is the source ISD-AS. (PARSE, only if needed)
	srcIA addr.IA
	// dstHost is the destination Host. (PARSE, only if dstIA is local)
	dstHost addr.HostAddr
	// srcHost is the source Host. (PARSE, only if needed)
	srcHost addr.HostAddr
	// infoF is the current Info Field, if any. (PARSE)
	infoF *spath.InfoField
	// hopF is the current Hop Field, if any. (PARSE)
	hopF *spath.HopField
	// ifCurr is the current interface ID. (PARSE)
	ifCurr *common.IFIDType
	// ifNext is the next interface ID, if any. (PARSE)
	ifNext *common.IFIDType
	// consDirFlag indicates if the packet is currently on a down path. (PARSE)
	consDirFlag *bool
	// HBHExt is the list of Hop-by-hop extensions, if any. (PARSE)
	HBHExt []rExtension
	// E2EExt is the list of end2end extensions, if any. (PARSE, only if needed)
	// TODO(kormat): The router currently ignores these.
	E2EExt []rExtension
	// L4Type is the type of the L4 protocol. If there isn't an L4 header, this will be L4None
	// (PROCESS, only if needed)
	L4Type common.L4ProtocolType
	// l4 is the L4 header, if any. (PROCESS, only if needed)
	l4 l4.L4Header
	// pld is the L4 payload, if any. (PROCESS, only if needed)
	pld common.Payload
	// hooks are registered callbacks to override/supplement normal processing. Their main use is
	// for extensions to modify packet handling.  (PARSE/PROCESS, only if needed)
	hooks hooks
	// SCMPError flags if the packet is an SCMP Error packet, in which case it should never trigger
	// an error response packet. (PARSE, if SCMP extension header is present)
	SCMPError bool
	// Logger is used to log messages associated with a packet. The Id field is automatically
	// included in the output.
	log.Logger
	// The current router context to process this packet.
	Ctx *rctx.Ctx
	// Reference count
	refCnt int32
	// Called by Release when the reference count hits 0
	Free func(*RtrPkt)
}

func NewRtrPkt() *RtrPkt {
	r := &RtrPkt{}
	r.Raw = make(common.RawBytes, pktBufSize)
	r.refCnt = 1
	return r
}

func (rp *RtrPkt) RefInc(val int) {
	atomic.AddInt32(&rp.refCnt, int32(val))
}

func (rp *RtrPkt) Release() {
	refCnt := atomic.AddInt32(&rp.refCnt, -1)
	if assert.On {
		assert.Mustf(refCnt >= 0, rp.ErrStr, "RtrPkt.refCnt be >= 0.")
	}
	if refCnt == 0 && rp.Free != nil {
		rp.Free(rp)
	}
	if assert.On {
		assert.Must(refCnt >= 0, "refCnt must be non-negative")
	}
}

// addrIFPair contains the overlay destination/source addresses, as well as the
// list of associated interface IDs.
type addrIFPair struct {
	Dst  *overlay.OverlayAddr
	Src  *overlay.OverlayAddr
	IfID common.IFIDType
	Sock string
}

// EgressPair contains the output function to send a packet with, along with an
// overlay destination address.
type EgressPair struct {
	S   *rctx.Sock
	Dst *overlay.OverlayAddr
}

type EgressRtrPkt struct {
	Rp  *RtrPkt
	Dst *overlay.OverlayAddr
}

// packetIdxs provides offsets into a packet buffer to the start of various
// fields. It is used heavily for parsing packets.
type packetIdxs struct {
	dstIA      int
	srcIA      int
	dstHost    int
	srcHost    int
	path       int
	nextHdrIdx hdrIdx
	hbhExt     []extnIdx
	e2eExt     []extnIdx
	l4         int
	pld        int
}

// hdrIdx provides the protocol type and index of a given L4/extension header.
type hdrIdx struct {
	Type  common.L4ProtocolType
	Index int
}

// extnIdx provides the extension type and index of an extension header.
type extnIdx struct {
	Type  common.ExtnType
	Index int
}

// Reset resets an RtrPkt to it's ~initial state, so it can be reused. Note
// that for performance reasons it doesn't actually clear the raw buffer, so
// reuse of an RtrPkt instance must ensure that the length of the buffer is
// set to the length of the new data, to prevent any of the old data from
// leaking through.
//
// Fields that are assumed to be overwritten (and hence aren't reset):
// TimeIn, CmnHdr, Logger
func (rp *RtrPkt) Reset() {
	rp.Id = ""
	// Reset the length of the buffer to the max size.
	rp.Raw = rp.Raw[:cap(rp.Raw)]
	rp.DirFrom = rcmn.DirUnset
	rp.Ingress.Dst = nil
	rp.Ingress.Src = nil
	rp.Ingress.IfID = 0
	rp.Egress = rp.Egress[:0]
	// CmnHdr doesn't contain any references.
	rp.IncrementedPath = false
	rp.idxs = packetIdxs{}
	rp.dstIA = addr.IA{}
	rp.srcIA = addr.IA{}
	rp.dstHost = nil
	rp.srcHost = nil
	rp.infoF = nil
	rp.hopF = nil
	rp.ifCurr = nil
	rp.ifNext = nil
	rp.consDirFlag = nil
	rp.HBHExt = rp.HBHExt[:0]
	rp.E2EExt = rp.E2EExt[:0]
	rp.L4Type = common.L4None
	rp.l4 = nil
	rp.pld = nil
	rp.hooks = hooks{}
	rp.SCMPError = false
	rp.Logger = nil
	rp.Ctx = nil
	rp.refCnt = 1
	rp.Free = nil
}

// ToScnPkt converts this RtrPkt into an spkt.ScnPkt. The verify argument
// defines whether verification errors should cause this conversion to fail or
// not. Setting this to false is useful when trying to convert a packet that is
// already known to have errors, for the purpose of sending an error response.
func (rp *RtrPkt) ToScnPkt(verify bool) (*spkt.ScnPkt, error) {
	var err error
	sp := &spkt.ScnPkt{}
	if sp.DstIA, err = rp.DstIA(); err != nil {
		return nil, err
	}
	if sp.SrcIA, err = rp.SrcIA(); err != nil {
		return nil, err
	}
	if sp.DstHost, err = rp.DstHost(); err != nil {
		return nil, err
	}
	if sp.SrcHost, err = rp.SrcHost(); err != nil {
		return nil, err
	}
	// spath.Path uses offsets relative to the start of its buffer, whereas the
	// SCION common header uses offsets relative to the start of the packet, so
	// convert from one to the other.
	sp.Path = &spath.Path{
		Raw:    rp.Raw[rp.idxs.path:rp.CmnHdr.HdrLenBytes()],
		InfOff: rp.CmnHdr.InfoFOffBytes() - rp.idxs.path,
		HopOff: rp.CmnHdr.HopFOffBytes() - rp.idxs.path,
	}
	for _, re := range rp.HBHExt {
		// Extract the higher-level SExtension (which is self-contained) from
		// the RtrPkt's rExtension (which may be tied to the underlying packet
		// buffer).
		se, err := re.GetExtn()
		if err != nil {
			return nil, err
		}
		sp.HBHExt = append(sp.HBHExt, se)
	}
	for _, re := range rp.E2EExt {
		// Same as for the HBHExts.
		se, err := re.GetExtn()
		if err != nil {
			return nil, err
		}
		sp.E2EExt = append(sp.E2EExt, se)
	}
	// Try to parse L4 and Payload, but we might fail to do so, ie. unsupported L4 protocol
	if sp.L4, err = rp.L4Hdr(verify); err != nil {
		if common.GetErrorMsg(err) != UnsupportedL4 {
			return nil, err
		}
	}
	if err == nil {
		// L4 header was parsed without error, then parse payload
		if sp.Pld, err = rp.Payload(verify); err != nil {
			if common.GetErrorMsg(err) != UnsupportedL4 {
				return nil, err
			}
		}
	}
	return sp, nil
}

// GetRaw returns slices of the underlying buffer corresponding to part of the
// packet identified by the blk argument. This is used, for example, by SCMP to
// quote parts of the packet in an error response.
func (rp *RtrPkt) GetRaw(blk scmp.RawBlock) common.RawBytes {
	pldOff := rp.idxs.pld
	if pldOff == 0 {
		// Either we failed to find the L4 header or the L4 header is an unknown protocol.
		pldOff = len(rp.Raw)
	}
	l4Off := rp.idxs.l4
	if l4Off == 0 {
		// L4 header not found, likely failed to parse extensions.
		// Use the last parsed header as L4 offset
		l4Off = rp.idxs.nextHdrIdx.Index
	}
	switch blk {
	case scmp.RawCmnHdr:
		return rp.Raw[:spkt.CmnHdrLen]
	case scmp.RawAddrHdr:
		return rp.Raw[rp.idxs.dstIA:rp.idxs.path]
	case scmp.RawPathHdr:
		return rp.Raw[rp.idxs.path:rp.CmnHdr.HdrLenBytes()]
	case scmp.RawExtHdrs:
		return rp.Raw[rp.CmnHdr.HdrLenBytes():l4Off]
	case scmp.RawL4Hdr:
		end := pldOff
		if _, ok := rp.l4.(*scmp.Hdr); ok {
			// XXX Special case, add SCMP info as part of the L4
			if meta, err := scmp.MetaFromRaw(rp.Raw[rp.idxs.pld:]); err == nil {
				end += int(scmp.MetaLen + (meta.InfoLen * common.LineLen))
			}
		}
		return rp.Raw[rp.idxs.l4:end]
	}
	rp.Crit("Invalid raw block requested", "blk", blk)
	return nil
}

// Bytes returns the raw bytes of the RtrPkt. Needed to implement rctx.OutputObj
// interface.
func (rp *RtrPkt) Bytes() common.RawBytes {
	return rp.Raw
}

func (rp *RtrPkt) String() string {
	// Pre-fetch required attributes, deliberately ignoring errors so as to
	// display as much information as can be gathered.
	rp.DstIA()
	rp.SrcIA()
	rp.DstHost()
	rp.SrcHost()
	rp.InfoF()
	rp.HopF()
	return fmt.Sprintf("Id: %v Dir from: %v Dst: %v %v Src: %v %v\n  InfoF: %v\n  HopF: %v",
		rp.Id, rp.DirFrom, rp.dstIA, rp.dstHost, rp.srcIA, rp.srcHost, rp.infoF, rp.hopF)
}

// ErrStr is a small utility method to combine an error message with a string
// representation of the packet, as well as a hex representation of the raw
// packet buffer.
func (rp *RtrPkt) ErrStr(desc string) string {
	return fmt.Sprintf("Error: %v\n  RtrPkt: %v\n  Raw: %v", desc, rp, rp.Raw)
}

// ErrStrf is a wrapper for ErrStr, which returns a callback to allow lazy
// evaluation of ErrStr. This is used for assert.Mustf in particular, so that
// when the assertion passes, the expensive call to ErrStr is avoided.
func (rp *RtrPkt) ErrStrf(desc string) func() string {
	return func() string {
		return rp.ErrStr(desc)
	}
}
