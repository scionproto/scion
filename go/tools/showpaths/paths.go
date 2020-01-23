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

// Simple show paths application for SCION.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/pathprobe"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	dstIAStr   = flag.String("dstIA", "", "Destination IA address: ISD-AS")
	srcIAStr   = flag.String("srcIA", "", "Source IA address: ISD-AS")
	sciondAddr = flag.String("sciond", sciond.DefaultSCIONDAddress, "SCIOND address")
	timeout    = flag.Duration("timeout", 5*time.Second, "Timeout in seconds")
	maxPaths   = flag.Int("maxpaths", 10, "Maximum number of paths")
	expiration = flag.Bool("expiration", false, "Show path expiration timestamps")
	refresh    = flag.Bool("refresh", false, "Set refresh flag for SCIOND path request")
	status     = flag.Bool("p", false, "Probe the paths and print out the statuses")
	version    = flag.Bool("version", false, "Output version information and exit.")
)

var (
	dstIA addr.IA
	srcIA addr.IA
	local snet.UDPAddr
)

func init() {
	flag.Var(&local, "local", "Local address to use for health checks")
	flag.Usage = flagUsage
}

func main() {
	log.AddLogConsFlags()
	validateFlags()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer log.LogPanicAndExit()

	ctx, cancelF := context.WithTimeout(context.Background(), *timeout)
	defer cancelF()
	paths, err := getPaths(ctx)
	if err != nil {
		LogFatal("Failed to get paths", "err", err)
	}
	fmt.Println("Available paths to", dstIA)
	var pathStatuses map[string]pathprobe.Status
	if *status {
		pathStatuses, err = pathprobe.Prober{
			Local: local,
			DstIA: dstIA,
		}.GetStatuses(ctx, paths)
		if err != nil {
			LogFatal("Failed to get status", "err", err)
		}
	}
	for i, path := range paths {
		fmt.Printf("[%2d] %s", i, fmt.Sprintf("%s", path))
		if *expiration {
			fmt.Printf(" Expires: %s (%s)", path.Expiry(),
				time.Until(path.Expiry()).Truncate(time.Second))
		}
		if *status {
			fmt.Printf(" Status: %s", pathStatuses[pathprobe.PathKey(path)])
		}
		fmt.Printf("\n")
	}
}

func validateFlags() {
	flag.Parse()
	var err error
	if *version {
		fmt.Print(env.VersionInfo())
		os.Exit(0)
	}
	if *dstIAStr == "" {
		LogFatal("Missing destination IA")
	} else {
		dstIA, err = addr.IAFromString(*dstIAStr)
		if err != nil {
			LogFatal("Unable to parse destination IA", "err", err)
		}
	}

	if *srcIAStr != "" {
		if srcIA, err = addr.IAFromString(*srcIAStr); err != nil {
			LogFatal("Unable to parse source IA", "err", err)
		}
	}

	if *status && (local.IA.IsZero() || local.Host == nil) {
		LogFatal("Local address is required for health checks")
	}
}

// TODO(lukedirtwalker): Replace this with snet.Router once we have the
// possibility to have the same functionality, i.e. refresh, fetch all paths.
// https://github.com/scionproto/scion/issues/3348
func getPaths(ctx context.Context) ([]snet.Path, error) {
	sdConn, err := sciond.NewService(*sciondAddr).Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("failed to connect to SCIOND", err)
	}
	paths, err := sdConn.Paths(ctx, dstIA, srcIA,
		sciond.PathReqFlags{Refresh: *refresh, PathCount: uint16(*maxPaths)})
	if err != nil {
		return nil, serrors.WrapStr("failed to retrieve paths from SCIOND", err)
	}
	return paths, nil
}

func flagUsage() {
	fmt.Fprintf(os.Stderr, `
Usage: showpaths [flags]

Lists available paths between SCION ASes. Paths might be retrieved from a local cache, and they
might not forward traffic successfully (for example, if a network link went down). To probe if the
paths are healthy, use -p.

flags:
`)
	flag.PrintDefaults()
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}
