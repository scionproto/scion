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

package showpaths

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/pathprobe"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
)

// Result contains all the discovered paths.
type Result struct {
	Destination addr.IA `json:"destination"`
	Paths       []Path  `json:"paths"`
}

// Path holds information about the discovered path.
type Path struct {
	FullPath    snet.Path `json:"-"`
	Fingerprint string    `json:"fingerprint"`
	Hops        []Hop     `json:"hops"`
	NextHop     string    `json:"next_hop"`
	Expiry      time.Time `json:"expiry"`
	MTU         uint16    `json:"mtu"`
	Status      string    `json:"status,omitempty"`
	StatusInfo  string    `json:"status_info,omitempty"`
	Local       net.IP    `json:"local_ip,omitempty"`
}

// Hop represents an hop on the path.
type Hop struct {
	IfID common.IFIDType `json:"ifid"`
	IA   addr.IA         `json:"isd_as"`
}

// Human writes human readable output to the writer.
func (r Result) Human(w io.Writer, showExpiration bool) {
	fmt.Fprintln(w, "Available paths to", r.Destination)
	for i, path := range r.Paths {
		fmt.Fprintf(w, "[%2d] %s", i, fmt.Sprintf("%s", path.FullPath))
		if showExpiration {
			ttl := time.Until(path.Expiry).Truncate(time.Second)
			fmt.Fprintf(w, " Expires: %s (%s)", path.Expiry, ttl)
		}
		if path.Status != "" {
			fmt.Fprintf(w, " Status: %s LocalIP: %s", path.Status, path.Local)
		}
		fmt.Fprintln(w)
	}
}

// JSON writes the showpaths result as a json object to the writer.
func (r Result) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Run lists the paths to the specified ISD-AS to stdout.
func Run(ctx context.Context, dst addr.IA, cfg Config) (*Result, error) {
	sdConn, err := sciond.NewService(cfg.SCIOND).Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("error connecting to SCIOND", err)
	}
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return nil, serrors.WrapStr("error determining local ISD-AS", err)
	}

	// TODO(lukedirtwalker): Replace this with snet.Router once we have the
	// possibility to have the same functionality, i.e. refresh, fetch all paths.
	// https://github.com/scionproto/scion/issues/3348
	paths, err := sdConn.Paths(ctx, dst, addr.IA{},
		sciond.PathReqFlags{Refresh: cfg.Refresh, PathCount: uint16(cfg.MaxPaths)})
	if err != nil {
		return nil, serrors.WrapStr("failed to retrieve paths from SCIOND", err)
	}

	var statuses map[string]pathprobe.Status
	var localIP net.IP
	if !cfg.NoProbe {
		// Resolve local IP in case it is not configured.
		if localIP = cfg.Local; localIP == nil {
			localIP, err = findDefaultLocalIP(ctx, sdConn)
			if err != nil {
				return nil, serrors.WrapStr("failed to determine local IP", err)
			}
		}
		statuses, err = pathprobe.Prober{
			DstIA:   dst,
			LocalIA: localIA,
			LocalIP: localIP,
		}.GetStatuses(ctx, paths)
		if err != nil {
			serrors.WrapStr("failed to get status", err)
		}
	}

	res := &Result{Destination: dst}
	for _, path := range paths {
		rpath := Path{
			FullPath:    path,
			Fingerprint: path.Fingerprint().String()[:16],
			NextHop:     path.UnderlayNextHop().String(),
			Expiry:      path.Expiry(),
			MTU:         path.MTU(),
			Local:       localIP,
		}
		for _, hop := range path.Interfaces() {
			rpath.Hops = append(rpath.Hops, Hop{IA: hop.IA(), IfID: hop.ID()})
		}
		if status, ok := statuses[pathprobe.PathKey(path)]; ok {
			rpath.Status = strings.ToLower(string(status.Status))
			rpath.StatusInfo = status.AdditionalInfo
		}
		res.Paths = append(res.Paths, rpath)
	}
	return res, nil
}

// TODO(matzf): this is a simple, hopefully temporary, workaround to not having
// wildcard addresses in snet.
// Here we just use a seemingly sensible default IP, but in the general case
// the local IP would depend on the next hop of selected path. This approach
// will not work in more complicated setups where e.g. different network
// interface are used to talk to different AS interfaces.
// Once a available, a wildcard address should be used and this should simply
// be removed.
//
// findDefaultLocalIP returns _a_ IP of this host in the local AS.
func findDefaultLocalIP(ctx context.Context, sciondConn sciond.Connector) (net.IP, error) {
	hostInLocalAS, err := findAnyHostInLocalAS(ctx, sciondConn)
	if err != nil {
		return nil, err
	}
	return addrutil.ResolveLocal(hostInLocalAS)
}

// findAnyHostInLocalAS returns the IP address of some (infrastructure) host in the local AS.
func findAnyHostInLocalAS(ctx context.Context, sciondConn sciond.Connector) (net.IP, error) {
	addr, err := sciond.TopoQuerier{Connector: sciondConn}.UnderlayAnycast(ctx, addr.SvcBS)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}
