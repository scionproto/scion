package pkti

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

type AddrHdr struct {
	DstIA, SrcIA     addr.IA
	DstHost, SrcHost addr.HostAddr
}

func NewAddrHdr(srcIA, srcHost, dstIA, dstHost string) *AddrHdr {
	dIA, _ := addr.IAFromString(dstIA)
	sIA, _ := addr.IAFromString(srcIA)
	return &AddrHdr{
		DstIA:   dIA,
		SrcIA:   sIA,
		DstHost: addr.HostFromIP(net.ParseIP(dstHost)),
		SrcHost: addr.HostFromIP(net.ParseIP(srcHost)),
	}
}

func ParseFromRaw(b common.RawBytes, srcT, dstT addr.HostAddrType) (*AddrHdr, error) {
	a := &AddrHdr{}
	if _, err := a.Parse(b, srcT, dstT); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AddrHdr) Parse(b common.RawBytes, srcT, dstT addr.HostAddrType) (int, error) {
	srcLen, err := addr.HostLen(srcT)
	if err != nil {
		return 0, err
	}
	dstLen, err := addr.HostLen(dstT)
	if err != nil {
		return 0, err
	}
	addrLen := ceil(2*addr.IABytes+int(dstLen+srcLen), common.LineLen)
	if addrLen > len(b) {
		return 0, fmt.Errorf("Buffer too short, expected=%d, actual=%d", addrLen, len(b))
	}
	a.DstIA = addr.IAFromRaw(b)
	a.SrcIA = addr.IAFromRaw(b[addr.IABytes:])
	offset := uint8(2 * addr.IABytes)
	a.DstHost, err = addr.HostFromRaw(b[offset:], dstT)
	if err != nil {
		return 0, err
	}
	offset += dstLen
	a.SrcHost, err = addr.HostFromRaw(b[offset:], srcT)
	if err != nil {
		return 0, err
	}
	return addrLen, nil
}

func (a *AddrHdr) Len() int {
	return ceil(2*addr.IABytes+a.DstHost.Size()+a.SrcHost.Size(), common.LineLen)
}

func (a *AddrHdr) Write(b common.RawBytes) int {
	offset := 0
	a.DstIA.Write(b[offset:])
	offset += addr.IABytes
	a.SrcIA.Write(b[offset:])
	offset += addr.IABytes
	// addr.HostAddr.Pack() is zero-copy, use it directly
	offset += copy(b[offset:], a.DstHost.Pack())
	offset += copy(b[offset:], a.SrcHost.Pack())
	// Zero memory padding
	addrPad := util.CalcPadding(offset, common.LineLen)
	zeroPad := b[offset : offset+addrPad]
	for i := range zeroPad {
		zeroPad[i] = 0
	}
	return offset + addrPad
}

func (a *AddrHdr) Eq(o *AddrHdr) bool {
	return a.DstIA.Eq(o.DstIA) && a.SrcIA.Eq(o.SrcIA) &&
		a.DstHost.Eq(o.DstHost) && a.SrcHost.Eq(o.SrcHost)
}

func (a *AddrHdr) String() string {
	return fmt.Sprintf("DstIA: %s, SrcIA: %s, DstHost: %s, SrcHost: %s",
		a.DstIA, a.SrcIA, a.DstHost, a.SrcHost)
}

func ceil(l, mult int) int {
	// mult must be base 2 value
	return (l + mult - 1) &^ (mult - 1)
}
