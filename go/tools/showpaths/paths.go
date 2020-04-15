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
	"net"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/pkg/showpaths"
)

var (
	dstIAStr   = flag.String("dstIA", "", "Destination IA address: ISD-AS")
	sciondAddr = flag.String("sciond", sciond.DefaultSCIONDAddress, "SCIOND address")
	timeout    = flag.Duration("timeout", 5*time.Second, "Timeout in seconds")
	maxPaths   = flag.Int("maxpaths", 10, "Maximum number of paths")
	expiration = flag.Bool("expiration", false, "Show path expiration timestamps")
	refresh    = flag.Bool("refresh", false, "Set refresh flag for SCIOND path request")
	json       = flag.Bool("json", false, "Write output as machine readable json")
	status     = flag.Bool("p", false, "Probe the paths and print out the statuses")
	localIPStr = flag.String("local", "", "(Optional) local IP address to use for health checks")
	version    = flag.Bool("version", false, "Output version information and exit.")
)

var (
	dstIA      addr.IA
	localIP    net.IP
	logConsole string
)

func init() {
	flag.Usage = flagUsage
}

func main() {
	flag.StringVar(&logConsole, "log.console", "info",
		"Console logging level: trace|debug|info|warn|error|crit")
	validateFlags()
	logCfg := log.Config{Console: log.ConsoleConfig{Level: logConsole}}
	if err := log.Setup(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer log.HandlePanic()

	ctx, cancelF := context.WithTimeout(context.Background(), *timeout)
	defer cancelF()
	cfg := showpaths.Config{
		Local:          localIP,
		SCIOND:         *sciondAddr,
		MaxPaths:       *maxPaths,
		ShowExpiration: *expiration,
		Refresh:        *refresh,
		Probe:          *status,
		JSON:           *json,
	}
	if err := showpaths.Run(ctx, dstIA, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
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
	if *localIPStr != "" {
		localIP = net.ParseIP(*localIPStr)
		if localIP == nil {
			LogFatal("Invalid local address")
		}
	}
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
