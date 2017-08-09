package reliable

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

var (
	NilAppAddr AppAddr
)

func init() {
	a, _ := addr.HostFromRaw(nil, addr.HostTypeNone)
	NilAppAddr = AppAddr{Addr: a, Port: 0}
}

// AppAddr is a L3 + L4 address container, it currently only supports UDP for L4.
type AppAddr struct {
	Addr addr.HostAddr
	Port uint16
}

func AppAddrFromRaw(buf common.RawBytes, addrType addr.HostAddrType) (*AppAddr, error) {
	var a AppAddr
	// NOTE: cerr is used to avoid nil stored in interface issue
	var cerr *common.Error
	addrLen, cerr := addr.HostLen(addrType)
	if cerr != nil {
		return nil, cerr
	}
	// Add 2 for port
	if len(buf) < int(addrLen)+2 {
		return nil, common.NewError("Buffer too small for address type", "expected", addrLen+2,
			"actual", len(buf))
	}

	a.Addr, cerr = addr.HostFromRaw(buf, addrType)
	if cerr != nil {
		return nil, common.NewError("Unable to parse address", "address",
			buf[:addrLen], "type", addrType)
	}
	a.Port = common.Order.Uint16(buf[addrLen:])
	return &a, nil
}

func (a *AppAddr) Write(buf common.RawBytes) (int, error) {
	if len(buf) < a.Len() {
		return 0, common.NewError("Unable to write AppAddr, buffer too small",
			"expected", a.Len(), "actual", len(buf))
	}
	a.writeAddr(buf)
	a.writePort(buf[a.Addr.Size():])
	return a.Len(), nil
}

func (a *AppAddr) Len() int {
	if a.Addr.Type() == addr.HostTypeNone {
		return a.Addr.Size()
	}
	return a.Addr.Size() + 2
}

func (a *AppAddr) writeAddr(buf common.RawBytes) {
	copy(buf, a.Addr.Pack())
}

func (a *AppAddr) writePort(buf common.RawBytes) {
	if a.Addr.Type() == addr.HostTypeNone {
		return
	}
	common.Order.PutUint16(buf, a.Port)
}
