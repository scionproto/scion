// Copyright 2020 ETH Zurich
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

// Package path implements snet.Path with full metadata
// This is used by libraries that provide paths for applications to use, such
// as the path combinator and the sciond API. Applications using snet will not
// usually make use of this package directly.
//
// TODO(matzf): perhaps moving empty path and partial path here too could be a nice cleanup.
package path

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

// Path is an snet.Path with full metadata
type Path struct {
	Dst     addr.IA
	SPath   spath.Path
	NextHop *net.UDPAddr
	IFaces  []snet.PathInterface
	Meta    PathMetadata
}

type PathMetadata struct {
	Mtu uint16
	Exp time.Time
}

func (p Path) UnderlayNextHop() *net.UDPAddr {
	if p.NextHop == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(p.NextHop.IP[:0:0], p.NextHop.IP...),
		Port: p.NextHop.Port,
		Zone: p.NextHop.Zone,
	}
}

func (p Path) Path() spath.Path {
	return p.SPath.Copy()
}

func (p Path) Interfaces() []snet.PathInterface {
	if p.IFaces == nil {
		return nil
	}
	intfs := make([]snet.PathInterface, 0, len(p.IFaces))
	for _, intf := range p.IFaces {
		intfs = append(intfs, intf)
	}
	return intfs
}

func (p Path) Destination() addr.IA {
	return p.Dst
}

func (p Path) Metadata() snet.PathMetadata {
	return p.Meta
}

func (p PathMetadata) MTU() uint16 {
	return p.Mtu
}

func (p PathMetadata) Expiry() time.Time {
	return p.Exp
}

func (p Path) Copy() snet.Path {
	return Path{
		IFaces:  append(p.IFaces[:0:0], p.IFaces...),
		NextHop: p.UnderlayNextHop(), // creates copy
		SPath:   p.Path(),            // creates copy
		Dst:     p.Dst,
		Meta:    p.Meta,
	}
}

func (p Path) String() string {
	hops := p.fmtInterfaces()
	return fmt.Sprintf("Hops: [%s] MTU: %d NextHop: %s",
		strings.Join(hops, ">"), p.Meta.Mtu, p.NextHop)
}

func (p Path) fmtInterfaces() []string {
	var hops []string
	if len(p.IFaces) == 0 {
		return hops
	}
	intf := p.IFaces[0]
	hops = append(hops, fmt.Sprintf("%s %d", intf.IA, intf.ID))
	for i := 1; i < len(p.IFaces)-1; i += 2 {
		inIntf := p.IFaces[i]
		outIntf := p.IFaces[i+1]
		hops = append(hops, fmt.Sprintf("%d %s %d", inIntf.ID, inIntf.IA, outIntf.ID))
	}
	intf = p.IFaces[len(p.IFaces)-1]
	hops = append(hops, fmt.Sprintf("%d %s", intf.ID, intf.IA))
	return hops
}
