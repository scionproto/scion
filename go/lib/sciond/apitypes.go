// Copyright 2019 Anapaya Systems
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

package sciond

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

type Path struct {
	interfaces []pathInterface
	overlay    *net.UDPAddr
	spath      *spath.Path
	mtu        uint16
	expiry     time.Time
}

func pathReplyToPaths(pathReply *PathReply) ([]snet.Path, error) {
	if pathReply.ErrorCode != ErrorOk {
		return nil, serrors.New("Path lookup had an error", "err_code", pathReply.ErrorCode)
	}
	paths := make([]snet.Path, 0, len(pathReply.Entries))
	for _, pe := range pathReply.Entries {
		p, err := pathReplyEntryToPath(pe)
		if err != nil {
			return nil, serrors.WrapStr("invalid path received", err)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func pathReplyEntryToPath(pe PathReplyEntry) (Path, error) {
	sp := spath.New(pe.Path.FwdPath)
	if err := sp.InitOffsets(); err != nil {
		return Path{}, serrors.WrapStr("path error", err)
	}
	overlayAddr := pe.HostInfo.Overlay()
	p := Path{
		interfaces: make([]pathInterface, 0, len(pe.Path.Interfaces)),
		overlay:    overlayAddr,
		spath:      sp,
		mtu:        pe.Path.Mtu,
		expiry:     pe.Path.Expiry(),
	}
	for _, intf := range pe.Path.Interfaces {
		p.interfaces = append(p.interfaces, pathInterface{ia: intf.IA(), id: intf.ID()})
	}
	return p, nil
}

func (p Path) Fingerprint() string {
	if len(p.interfaces) == 0 {
		return ""
	}
	h := sha256.New()
	for _, intf := range p.interfaces {
		binary.Write(h, common.Order, intf.IA().IAInt())
		binary.Write(h, common.Order, intf.ID())
	}
	return string(h.Sum(nil))
}

func (p Path) OverlayNextHop() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(p.overlay.IP[:0:0], p.overlay.IP...),
		Port: p.overlay.Port,
		Zone: p.overlay.Zone,
	}
}

func (p Path) Path() *spath.Path {
	return p.spath.Copy()
}

func (p Path) Interfaces() []snet.PathInterface {
	if p.interfaces == nil {
		return nil
	}
	intfs := make([]snet.PathInterface, 0, len(p.interfaces))
	for _, intf := range p.interfaces {
		intfs = append(intfs, intf)
	}
	return intfs
}

func (p Path) Destination() addr.IA {
	if len(p.interfaces) == 0 {
		return addr.IA{}
	}
	return p.interfaces[len(p.interfaces)-1].IA()
}

func (p Path) MTU() uint16 {
	return p.mtu
}

func (p Path) Expiry() time.Time {
	return p.expiry
}

func (p Path) Copy() snet.Path {
	panic("TODO")
}

func (p Path) String() string {
	hops := p.fmtInterfaces()
	return fmt.Sprintf("Hops: [%s] MTU: %d, NextHop: %s:%d",
		strings.Join(hops, ">"), p.mtu, p.overlay.IP, p.overlay.Port)
}

func (p Path) fmtInterfaces() []string {
	var hops []string
	if len(p.interfaces) == 0 {
		return hops
	}
	intf := p.interfaces[0]
	hops = append(hops, fmt.Sprintf("%s %d", intf.IA(), intf.ID()))
	for i := 1; i < len(p.interfaces)-1; i += 2 {
		inIntf := p.interfaces[i]
		outIntf := p.interfaces[i+1]
		hops = append(hops, fmt.Sprintf("%d %s %d", inIntf.ID(), inIntf.IA(), outIntf.ID()))
	}
	intf = p.interfaces[len(p.interfaces)-1]
	hops = append(hops, fmt.Sprintf("%d %s", intf.ID(), intf.IA()))
	return hops
}

type pathInterface struct {
	id common.IFIDType
	ia addr.IA
}

func (i pathInterface) ID() common.IFIDType { return i.id }
func (i pathInterface) IA() addr.IA         { return i.ia }
