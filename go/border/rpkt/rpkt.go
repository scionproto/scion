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
// This differs from the higher-level github.com/netsec-ethz/scion/go/lib/spkt
// package by being tied to an underlying buffer, which greatly improves
// processing performance at the expense of flexibility.
package rpkt

import (
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

// pktBufSize is the maxiumum size of a packet buffer.
// FIXME(kormat): this should be reduced as soon as we respect the actual link MTU.
const pktBufSize = 1 << 16

// callbacks is an anonymous struct used for functions supplied by the router
// for various processing tasks.
var callbacks struct {
	locOutFs   map[int]OutputFunc
	intfOutFs  map[spath.IntfID]OutputFunc
	ifStateUpd func(proto.IFStateInfos)
	revTokenF  func(RevTokenCallbackArgs)
}

// Init takes callback functions provided by the router and stores them for use
// by the rpkt package.
func Init(locOut map[int]OutputFunc, intfOut map[spath.IntfID]OutputFunc,
	ifStateUpd func(proto.IFStateInfos), revTokenF func(RevTokenCallbackArgs)) {
	callbacks.locOutFs = locOut
	callbacks.intfOutFs = intfOut
	callbacks.ifStateUpd = ifStateUpd
	callbacks.revTokenF = revTokenF
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
	// calculations. Note that this is a monotonic time value with an arbitrary
	// epoch, and can't be used to refer to a particular clock time. (RECV)
	TimeIn time.Duration
	// DirFrom is the direction from which the packet was received. (RECV)
	DirFrom Dir
	// DirTo is the direction to which the packet is travelling. (PARSE)
	DirTo Dir
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
	// srcIA is the source ISD-AS. (PARSE, only if needed)
	srcIA *addr.ISD_AS
	// srcHost is the source Host. (PARSE, only if needed)
	srcHost addr.HostAddr
	// dstIA is the destination ISD-AS. (PARSE)
	dstIA *addr.ISD_AS
	// dstHost is the destination Host. (PARSE, only if dstIA is local)
	dstHost addr.HostAddr
	// infoF is the current Info Field, if any. (PARSE)
	infoF *spath.InfoField
	// hopF is the current Hop Field, if any. (PARSE)
	hopF *spath.HopField
	// ifCurr is the current interface ID. (PARSE)
	ifCurr *spath.IntfID
	// ifNext is the next interface ID, if any. (PARSE)
	ifNext *spath.IntfID
	// upFlag indicates if the packet is currently on an up path. (PARSE)
	upFlag *bool
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
}

func NewRtrPkt() *RtrPkt {
	r := &RtrPkt{}
	r.Raw = make(common.RawBytes, pktBufSize)
	return r
}

// Dir represents a packet direction. It is used to designate where a packet
// came from, and where it is going to.
type Dir int

const (
	// DirUnset is the zero-value for Dir, and means the direction hasn't been initialized.
	DirUnset Dir = iota
	// DirSelf means the packet is going to/coming from this router.
	DirSelf
	// DirLocal means the packet is going to/coming from the local ISD-AS.
	DirLocal
	// DirExternal means the packet is going to/coming from another ISD-AS.
	DirExternal
)

func (d Dir) String() string {
	switch d {
	case DirUnset:
		return "Unset"
	case DirSelf:
		return "Self"
	case DirLocal:
		return "Local"
	case DirExternal:
		return "External"
	default:
		return "UNKNOWN"
	}
}

// addrIFPair contains the overlay source/destination addresses, as well as the
// list of associated interface IDs.
type addrIFPair struct {
	Src   *net.UDPAddr
	Dst   *net.UDPAddr
	IfIDs []spath.IntfID
}

// OutputFunc is the type of callback required for sending a packet.
type OutputFunc func(*RtrPkt, *net.UDPAddr)

// EgressPair contains the output function to send a packet with, along with an
// overlay destination address.
type EgressPair struct {
	F   OutputFunc
	Dst *net.UDPAddr
}

// packetIdxs provides offsets into a packet buffer to the start of various
// fields. It is used heavily for parsing packets.
type packetIdxs struct {
	srcIA      int
	srcHost    int
	dstIA      int
	dstHost    int
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
// Id, TimeIn, CmnHdr, Logger
func (rp *RtrPkt) Reset() {
	// Reset the length of the buffer to the max size.
	rp.Raw = rp.Raw[:cap(rp.Raw)-1]
	rp.DirFrom = DirUnset
	rp.DirTo = DirUnset
	rp.Ingress.Src = nil
	rp.Ingress.Dst = nil
	rp.Ingress.IfIDs = nil
	rp.Egress = rp.Egress[:0]
	rp.IncrementedPath = false
	rp.idxs = packetIdxs{}
	rp.srcIA = nil
	rp.srcHost = nil
	rp.dstIA = nil
	rp.dstHost = nil
	rp.infoF = nil
	rp.hopF = nil
	rp.ifCurr = nil
	rp.ifNext = nil
	rp.upFlag = nil
	rp.HBHExt = rp.HBHExt[:0]
	rp.E2EExt = rp.E2EExt[:0]
	rp.L4Type = common.L4None
	rp.l4 = nil
	rp.pld = nil
	rp.hooks = hooks{}
	rp.SCMPError = false
}

// ToScnPkt converts this RtrPkt into an spkt.ScnPkt. The verify argument
// defines whether verification errors should cause this conversion to fail or
// not. Setting this to false is useful when trying to convert a packet that is
// already known to have errors, for the purpose of sending an error response.
func (rp *RtrPkt) ToScnPkt(verify bool) (*spkt.ScnPkt, *common.Error) {
	var err *common.Error
	sp := &spkt.ScnPkt{}
	if sp.SrcIA, err = rp.SrcIA(); err != nil {
		return nil, err
	}
	if sp.SrcHost, err = rp.SrcHost(); err != nil {
		return nil, err
	}
	if sp.DstIA, err = rp.DstIA(); err != nil {
		return nil, err
	}
	if sp.DstHost, err = rp.DstHost(); err != nil {
		return nil, err
	}
	// spath.Path uses offsets relative to the start of its buffer, whereas the
	// SCION common header uses offsets relative to the start of the packet, so
	// convert from one to the other.
	sp.Path = &spath.Path{
		Raw:    rp.Raw[rp.idxs.path:rp.CmnHdr.HdrLen],
		InfOff: rp.CmnHdr.CurrInfoF - uint8(rp.idxs.path),
		HopOff: rp.CmnHdr.CurrHopF - uint8(rp.idxs.path),
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
	if sp.L4, err = rp.L4Hdr(verify); err != nil {
		return nil, err
	}
	if sp.Pld, err = rp.Payload(verify); err != nil {
		return nil, err
	}
	return sp, nil
}

// GetRaw returns slices of the underlying buffer corresponding to part of the
// packet identified by the blk argument. This is used, for example, by SCMP to
// quote parts of the packet in an error response.
func (rp *RtrPkt) GetRaw(blk scmp.RawBlock) common.RawBytes {
	switch blk {
	case scmp.RawCmnHdr:
		return rp.Raw[:spkt.CmnHdrLen]
	case scmp.RawAddrHdr:
		return rp.Raw[rp.idxs.srcIA:rp.idxs.path]
	case scmp.RawPathHdr:
		return rp.Raw[rp.idxs.path:rp.CmnHdr.HdrLen]
	case scmp.RawExtHdrs:
		return rp.Raw[rp.CmnHdr.HdrLen:rp.idxs.l4]
	case scmp.RawL4Hdr:
		return rp.Raw[rp.idxs.l4:rp.idxs.pld]
	}
	rp.Crit("Invalid raw block requested", "blk", blk)
	return nil
}

func (rp *RtrPkt) String() string {
	// Pre-fetch required attributes, deliberately ignoring errors so as to
	// display as much information as can be gathered.
	rp.SrcIA()
	rp.SrcHost()
	rp.DstIA()
	rp.DstHost()
	rp.InfoF()
	rp.HopF()
	return fmt.Sprintf("Id: %v Dir from/to: %v/%v Src: %v %v Dst: %v %v\n  InfoF: %v\n  HopF: %v",
		rp.Id, rp.DirFrom, rp.DirTo, rp.srcIA, rp.srcHost, rp.dstIA, rp.dstHost, rp.infoF, rp.hopF)
}

// ErrStr is a small utility method to combine an error message with a string
// representation of the packet, as well as a hex representation of the raw
// packet buffer.
func (rp *RtrPkt) ErrStr(desc string) string {
	return fmt.Sprintf("Error: %v\n  RtrPkt: %v\n  Raw: %v", desc, rp, rp.Raw)
}
