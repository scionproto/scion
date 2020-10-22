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

	"github.com/fatih/color"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/pathprobe"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/pkg/app"
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
func (r Result) Human(w io.Writer, showExpiration, colored bool) {
	noColor := color.New()
	keys := noColor
	values := noColor
	header := noColor
	statusGood := noColor
	statusBad := noColor
	if colored {
		keys = color.New(color.FgHiCyan)
		values = noColor
		header = color.New(color.FgHiBlack)
		statusGood = color.New(color.FgGreen)
		statusBad = color.New(color.FgRed)
	}

	sectionHeader := func(intfs int) {
		header.Fprintf(w, "%d Hops:\n", (intfs/2)+1)
	}
	sectionHeader(len(r.Paths[0].Hops))
	for i, path := range r.Paths {
		if i != 0 && len(r.Paths[i-1].Hops) != len(path.Hops) {
			sectionHeader(len(path.Hops))
		}

		entries := []string{app.ColorPath(path.FullPath, app.WithDisableColor(!colored))}
		if showExpiration {
			ttl := time.Until(path.Expiry).Truncate(time.Second)
			entries = append(entries, fmt.Sprintf("%s: %s (%s)",
				keys.Sprint("Expires"), values.Sprint(path.Expiry), values.Sprint(ttl)),
			)
		}
		if path.Status != "" {
			statusColor := statusBad
			if strings.EqualFold(path.Status, string(pathprobe.StatusAlive)) {
				statusColor = statusGood
			}
			entries = append(entries, fmt.Sprintf("%s: %s",
				keys.Sprint("Status"), statusColor.Sprint(path.Status)),
			)
			entries = append(entries, fmt.Sprintf("%s: %s",
				keys.Sprint("LocalIP"), values.Sprint(path.Local)),
			)
		}
		fmt.Fprintf(w, "[%2d] %s\n", i, strings.Join(entries, " "))
	}
}

// JSON writes the showpaths result as a json object to the writer.
func (r Result) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// Alive returns the number of alive paths.
func (r Result) Alive() int {
	var c int
	for _, path := range r.Paths {
		if strings.EqualFold(path.Status, string(pathprobe.StatusAlive)) {
			c++
		}
	}
	return c
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
	allPaths, err := sdConn.Paths(ctx, dst, addr.IA{},
		sciond.PathReqFlags{Refresh: cfg.Refresh})
	if err != nil {
		return nil, serrors.WrapStr("failed to retrieve paths from SCIOND", err)
	}
	paths, err := app.Filter(cfg.Sequence, allPaths)
	if err != nil {
		return nil, err
	}
	if cfg.MaxPaths != 0 && len(paths) > cfg.MaxPaths {
		paths = paths[:cfg.MaxPaths]
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
		p := pathprobe.FilterEmptyPaths(paths)
		statuses, err = pathprobe.Prober{
			DstIA:   dst,
			LocalIA: localIA,
			LocalIP: localIP,
		}.GetStatuses(ctx, p)
		if err != nil {
			serrors.WrapStr("failed to get status", err)
		}
	}
	app.SortPaths(paths)
	res := &Result{Destination: dst}
	for _, path := range paths {
		fingerprint := "local"
		if len(path.Interfaces()) > 0 {
			fp := snet.Fingerprint(path).String()
			fingerprint = fp[:16]
		}
		var nextHop string
		if nh := path.UnderlayNextHop(); nh != nil {
			nextHop = path.UnderlayNextHop().String()
		}
		rpath := Path{
			FullPath:    path,
			Fingerprint: fingerprint,
			NextHop:     nextHop,
			Expiry:      path.Metadata().Expiry(),
			MTU:         path.Metadata().MTU(),
			Local:       localIP,
			Hops:        []Hop{},
		}
		for _, hop := range path.Interfaces() {
			rpath.Hops = append(rpath.Hops, Hop{IA: hop.IA, IfID: hop.ID})
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
	addr, err := sciond.TopoQuerier{Connector: sciondConn}.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}
