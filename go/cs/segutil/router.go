// Copyright 2020 Anapaya Systems
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

package segutil

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

// Router returns paths backed by the local path database.
type Router struct {
	Pather segfetcher.Pather
}

// Route returns a path from the local AS to dst. If dst matches the local
// AS, an empty path is returned.
func (r *Router) Route(ctx context.Context, dst addr.IA) (snet.Path, error) {
	paths, err := r.AllRoutes(ctx, dst)
	if err != nil {
		return nil, err
	}
	return paths[0], nil
}

// AllRoutes is similar to Route except that it returns multiple paths.
func (r *Router) AllRoutes(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	cPaths, err := r.Pather.GetPaths(ctx, dst, false)
	if err != nil {
		return nil, err
	}
	var paths []snet.Path
	var errs serrors.List
	for _, path := range cPaths {
		p, err := r.translate(path, dst)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return nil, serrors.New("no paths after translation", "errs", errs.ToError())
	}
	return paths, nil
}

func (r *Router) translate(comb *combinator.Path, dst addr.IA) (path, error) {
	if len(comb.Interfaces) == 0 {
		return path{dst: dst}, nil
	}
	buf := &bytes.Buffer{}
	if _, err := comb.WriteTo(buf); err != nil {
		return path{}, err
	}
	var sp *spath.Path
	if !comb.HeaderV2 {
		sp = spath.New(buf.Bytes())
		if err := sp.InitOffsets(); err != nil {
			return path{}, err
		}
	} else {
		sp = spath.NewV2(buf.Bytes(), false)
	}
	nextHop, ok := r.Pather.TopoProvider.Get().UnderlayNextHop(comb.Interfaces[0].ID)
	if !ok {
		return path{}, serrors.New("Unable to find first-hop BR for path",
			"ifid", comb.Interfaces[0].ID)
	}
	p := path{
		interfaces: make([]snet.PathInterface, len(comb.Interfaces)),
		underlay:   nextHop,
		spath:      sp,
		metadata: pathMetadata{
			mtu:    comb.Mtu,
			expiry: comb.ComputeExpTime(),
		},
	}
	copy(p.interfaces, comb.Interfaces)
	return p, nil
}

type path struct {
	interfaces []snet.PathInterface
	underlay   *net.UDPAddr
	spath      *spath.Path
	dst        addr.IA
	metadata   pathMetadata
}

type pathMetadata struct {
	mtu    uint16
	expiry time.Time
}

func (p path) UnderlayNextHop() *net.UDPAddr {
	if p.underlay == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(p.underlay.IP[:0:0], p.underlay.IP...),
		Port: p.underlay.Port,
		Zone: p.underlay.Zone,
	}
}

func (p path) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p path) Interfaces() []snet.PathInterface {
	if p.interfaces == nil {
		return nil
	}
	intfs := make([]snet.PathInterface, 0, len(p.interfaces))
	for _, intf := range p.interfaces {
		intfs = append(intfs, intf)
	}
	return intfs
}

func (p path) Destination() addr.IA {
	if len(p.interfaces) == 0 {
		return p.dst
	}
	return p.interfaces[len(p.interfaces)-1].IA
}

func (p path) Metadata() snet.PathMetadata {
	return p.metadata
}

func (p path) Copy() snet.Path {
	return path{
		interfaces: append(p.interfaces[:0:0], p.interfaces...),
		underlay:   p.UnderlayNextHop(), // creates copy
		spath:      p.Path(),            // creates copy
		metadata:   p.metadata,
	}
}

func (p path) String() string {
	hops := p.fmtInterfaces()
	return fmt.Sprintf("Hops: [%s] MTU: %d, NextHop: %s",
		strings.Join(hops, ">"), p.Metadata().MTU(), p.UnderlayNextHop())
}

func (p path) fmtInterfaces() []string {
	var hops []string
	if len(p.interfaces) == 0 {
		return hops
	}
	intf := p.interfaces[0]
	hops = append(hops, fmt.Sprintf("%s %d", intf.IA, intf.ID))
	for i := 1; i < len(p.interfaces)-1; i += 2 {
		inIntf := p.interfaces[i]
		outIntf := p.interfaces[i+1]
		hops = append(hops, fmt.Sprintf("%d %s %d", inIntf.ID, inIntf.IA, outIntf.ID))
	}
	intf = p.interfaces[len(p.interfaces)-1]
	hops = append(hops, fmt.Sprintf("%d %s", intf.ID, intf.IA))
	return hops
}

func (m pathMetadata) MTU() uint16 {
	return m.mtu
}

func (m pathMetadata) Expiry() time.Time {
	return m.expiry
}
