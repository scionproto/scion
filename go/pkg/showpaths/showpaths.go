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
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/pathprobe"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
)

// Run lists the paths to the specified ISD-AS to stdout.
func Run(ctx context.Context, dst addr.IA, options ...Option) error {
	opts := invokeOptions(options)

	sdConn, err := sciond.NewService(opts.sciond).Connect(ctx)
	if err != nil {
		return serrors.WrapStr("error connecting to SCIOND", err)
	}
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return serrors.WrapStr("error determining local ISD-AS", err)
	}

	// TODO(lukedirtwalker): Replace this with snet.Router once we have the
	// possibility to have the same functionality, i.e. refresh, fetch all paths.
	// https://github.com/scionproto/scion/issues/3348
	paths, err := sdConn.Paths(ctx, dst, addr.IA{},
		sciond.PathReqFlags{Refresh: opts.refresh, PathCount: uint16(opts.maxPaths)})
	if err != nil {
		return serrors.WrapStr("failed to retrieve paths from SCIOND", err)
	}

	fmt.Println("Available paths to", dst)
	var pathStatuses map[string]pathprobe.Status
	if opts.probe {
		localIP := opts.local
		if localIP == nil {
			localIP, err = findDefaultLocalIP(ctx, sdConn)
			if err != nil {
				return serrors.WrapStr("failed to determine local IP", err)
			}
		}
		pathStatuses, err = pathprobe.Prober{
			DstIA:   dst,
			LocalIA: localIA,
			LocalIP: localIP,
		}.GetStatuses(ctx, paths)
		if err != nil {
			serrors.WrapStr("failed to get status", err)
		}
	}
	for i, path := range paths {
		fmt.Printf("[%2d] %s", i, fmt.Sprintf("%s", path))
		if opts.expiration {
			fmt.Printf(" Expires: %s (%s)", path.Expiry(),
				time.Until(path.Expiry()).Truncate(time.Second))
		}
		if pathStatuses != nil {
			fmt.Printf(" Status: %s", pathStatuses[pathprobe.PathKey(path)])
		}
		fmt.Printf("\n")
	}
	return nil
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
	addr, err := sciond.TopoQuerier{Connector: sciondConn}.OverlayAnycast(ctx, addr.SvcBS)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}
